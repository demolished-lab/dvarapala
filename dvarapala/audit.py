"""Tamper-evident, SHA-256 hash-chained audit log (JSONL).

Every record's ``hash_prev`` points at the previous record's ``hash_self``.
Editing, deleting, or *truncating* history breaks verification::

    dvarapala verify audit.jsonl            # chain + corruption check
    dvarapala verify --strict audit.jsonl   # additionally require anchor

Production hardening in this version:

- **Chain-head anchoring.** Every append atomically updates a sidecar
  ``<path>.head`` file holding the tip hash. ``verify()`` compares the log's
  last record against the anchor, so deleting trailing entries or rewriting
  the tail is detected (a bare hash chain alone cannot see truncation).
- **Corruption detection.** Unreadable/torn lines fail verification instead
  of being silently skipped.
- **Cross-process safety.** Appends take an advisory lock (``fcntl`` on
  POSIX, ``msvcrt`` on Windows), re-scan the tip inside the lock, and append.
  Multiple processes can share one audit file without breaking the chain.
- **Durability mode.** ``AuditLog(path, durable=True)`` fsyncs every append.

Stdlib only. Memory mode (path=None) keeps records in a list — useful for
tests and embedding.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, TypeVar

SCHEMA_VERSION = 2

_READ_CHUNK = 8192


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")


@dataclass
class AuditRecord:
    timestamp: float
    event: str  # allowed | denied | blocked | rate_limited | executed | failed
    tool: str
    action_type: str
    risk: str = ""
    decision_reason: str = ""
    rule_id: str | None = None
    source: str = ""
    args: str = ""
    # Causal fields
    run_id: str = ""
    step: int | None = None
    parent_step: int | None = None
    context_refs: list[str] = field(default_factory=list)
    alternatives_considered: list[str] = field(default_factory=list)
    state_delta: str = ""
    error: str = ""
    hash_prev: str = ""
    hash_self: str = ""
    schema_version: int = SCHEMA_VERSION

    def payload(self) -> dict:
        """Full record for serialization, including ``hash_self``."""
        return asdict(self)

    def compute_hash(self) -> str:
        """SHA-256 of everything except ``hash_self`` itself."""
        d = self.payload()
        d.pop("hash_self", None)
        return hashlib.sha256(_canonical(d)).hexdigest()

    def brief(self) -> str:
        ts = f"{self.timestamp:.0f}"
        head = f"[{ts}] {self.event:<13} {self.risk:<8} {self.tool}"
        bits = [head]
        if self.decision_reason:
            bits.append(f"  reason: {self.decision_reason}")
        if self.rule_id:
            bits.append(f"  rule: {self.rule_id}")
        if self.run_id:
            loc = f"run={self.run_id}"
            if self.step is not None:
                loc += f" step={self.step}"
            bits.append(f"  {loc}")
        return "\n".join(bits)


class _FileLock:
    """Advisory exclusive lock via a dedicated lockfile (cross-process)."""

    _SelfT = TypeVar("_SelfT", bound="_FileLock")

    def __init__(self, path: Path):
        self.path = path
        self._fh: Any = None

    def __enter__(self: _FileLock._SelfT) -> _FileLock._SelfT:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self.path, "a+b")
        fd = self._fh.fileno()
        try:  # POSIX
            import fcntl  # type: ignore[import-not-found]

            fcntl.lockf(fd, fcntl.LOCK_EX)
        except ImportError:  # Windows
            import msvcrt  # type: ignore[import-not-found]

            self._fh.seek(0)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        return self

    def __exit__(self, *exc: object) -> None:
        try:
            fd = self._fh.fileno()
            try:
                import fcntl  # type: ignore[import-not-found]

                fcntl.lockf(fd, fcntl.LOCK_UN)
            except ImportError:
                import msvcrt  # type: ignore[import-not-found]

                self._fh.seek(0)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        finally:
            self._fh.close()
            self._fh = None


class AuditLog:
    """Append-only JSONL audit log with per-record hash chaining."""

    def __init__(self, path: str | Path | None = None, *,
                 durable: bool = False):
        self.path = Path(path) if path else None
        self.durable = durable
        self.anchor_path = (
            self.path.with_name(self.path.name + ".head") if self.path else None
        )
        self._lock = threading.Lock()
        self._memory: list[AuditRecord] = []
        self._last_hash = ""
        self._anchored_memory = ""
        if self.path and self.path.exists():
            self._last_hash = self._scan_last_hash()

    @property
    def mode(self) -> str:
        return "file" if self.path else "memory"

    # ── append ─────────────────────────────────────────────────

    def append(self, record: AuditRecord) -> AuditRecord:
        with self._lock:
            if self.path:
                lock_path = self.path.with_name(self.path.name + ".lock")
                with _FileLock(lock_path):
                    # Re-scan the tip inside the lock so concurrent writers
                    # chain correctly onto each other's records.
                    self._last_hash = self._scan_last_hash()
                    record.hash_prev = self._last_hash
                    record.hash_self = record.compute_hash()
                    self.path.parent.mkdir(parents=True, exist_ok=True)
                    line = json.dumps(record.payload(), sort_keys=True,
                                      ensure_ascii=False) + "\n"
                    with open(self.path, "a", encoding="utf-8",
                              newline="\n") as f:
                        f.write(line)
                        if self.durable:
                            f.flush()
                            os.fsync(f.fileno())
                    self._write_anchor(record.hash_self)
                    self._last_hash = record.hash_self
            else:
                record.hash_prev = self._last_hash
                record.hash_self = record.compute_hash()
                self._memory.append(record)
                self._last_hash = record.hash_self
        return record

    # ── verification ───────────────────────────────────────────

    def verify(self, *, strict: bool = False) -> tuple[bool, str]:
        """Verify hash chain, detect corruption, and (when anchored) detect
        truncation or tail rewriting. ``strict=True`` requires an anchor."""
        if not self.path:
            records = list(self._memory)
            malformed = 0
        else:
            records, malformed = self._read_all_checked()

        if malformed:
            return False, (f"{malformed} unreadable/corrupt line(s); "
                           "log integrity compromised")
        if not records:
            if strict and self.path and not self._read_anchor():
                return False, "strict mode: no anchor found"
            return True, "empty audit log"

        for i, rec in enumerate(records):
            if rec.hash_self != rec.compute_hash():
                return False, f"entry {i}: hash mismatch (tampered)"
            if i == 0:
                if rec.hash_prev:
                    return False, "entry 0: hash_prev should be empty"
            elif rec.hash_prev != records[i - 1].hash_self:
                return False, f"entry {i}: chain broken (prev hash mismatch)"

        anchor = self._read_anchor() if self.path else None
        if anchor:
            tip = records[-1].hash_self
            if tip != anchor.get("hash_self"):
                return False, ("tail mismatch: last entry does not match "
                               "anchored head (truncated or rewritten)")
            return True, (f"chain intact and anchored: "
                          f"{len(records)} entries verified")
        if strict:
            return False, "strict mode: no anchor found"
        return True, f"chain intact: {len(records)} entries verified"

    def anchor_hash(self) -> str:
        """Return the anchored tip hash ('' when absent)."""
        if not self.path:
            return self._anchored_memory
        a = self._read_anchor()
        return str(a.get("hash_self", "")) if a else ""

    def refresh_anchor(self) -> str:
        """Re-anchor to the current tip (use after intentional pruning)."""
        with self._lock:
            if not self.path:
                self._anchored_memory = (self._memory[-1].hash_self
                                         if self._memory else "")
                return self._anchored_memory
            records, _ = self._read_all_checked()
            if not records:
                raise ValueError("cannot anchor an empty log")
            tip = records[-1].hash_self
            lock_path = self.path.with_name(self.path.name + ".lock")
            with _FileLock(lock_path):
                self._write_anchor(tip)
            return tip

    def tail(self, n: int = 50) -> list[AuditRecord]:
        records, _ = self._read_all_checked()
        return records[-n:]

    # ── internals ──────────────────────────────────────────────

    def _read_all(self) -> list[AuditRecord]:
        records, _ = self._read_all_checked()
        return records

    def _read_all_checked(self) -> tuple[list[AuditRecord], int]:
        """Return (records, malformed_line_count)."""
        if not self.path:
            return list(self._memory), 0
        if not self.path.exists():
            return [], 0
        records: list[AuditRecord] = []
        malformed = 0
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(AuditRecord(**json.loads(line)))
                except (json.JSONDecodeError, TypeError):
                    malformed += 1  # torn/corrupt lines fail verification
        return records, malformed

    def _scan_last_hash(self) -> str:
        try:
            size = self.path.stat().st_size  # type: ignore[union-attr]
            with open(self.path, "rb") as f:
                f.seek(max(0, size - _READ_CHUNK))
                chunk = f.read()
            lines = [ln for ln in chunk.split(b"\n") if ln.strip()]
            if lines:
                data = json.loads(lines[-1].decode("utf-8"))
                return data.get("hash_self", "")
        except (OSError, json.JSONDecodeError):
            pass
        return ""

    def _read_anchor(self) -> dict | None:
        assert self.anchor_path is not None
        try:
            if not self.anchor_path.exists():
                return None
            data = json.loads(self.anchor_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except (OSError, json.JSONDecodeError):
            return None

    def _write_anchor(self, tip_hash: str) -> None:
        """Atomically persist the chain tip so truncation is detectable."""
        assert self.anchor_path is not None
        payload = json.dumps({
            "schema_version": SCHEMA_VERSION,
            "hash_self": tip_hash,
            "updated": time.time(),
        }, sort_keys=True)
        tmp = self.anchor_path.with_name(
            f"{self.anchor_path.name}.{os.getpid()}.tmp")
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, self.anchor_path)
