"""Tamper-evident, SHA-256 hash-chained audit log (JSONL).

Every record's ``hash_prev`` points at the previous record's ``hash_self``.
Editing or deleting any historical entry breaks the chain, which
:meth:`AuditLog.verify` detects. The record schema includes causal fields
(``run_id``, ``step``, ``parent_step``, ``context_refs``,
``alternatives_considered``, ``state_delta``) from day one so that failure
attribution ("why did the agent do that?") can be built on top without
re-instrumentation.

Stdlib only. Memory mode (path=None) keeps records in a list — useful for
tests and embedding.
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

SCHEMA_VERSION = 1

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


class AuditLog:
    """Append-only JSONL audit log with per-record hash chaining."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._memory: list[AuditRecord] = []
        self._last_hash = ""
        if self.path and self.path.exists():
            self._last_hash = self._scan_last_hash()

    @property
    def mode(self) -> str:
        return "file" if self.path else "memory"

    def append(self, record: AuditRecord) -> AuditRecord:
        with self._lock:
            record.hash_prev = self._last_hash
            record.hash_self = record.compute_hash()
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                line = json.dumps(record.payload(), sort_keys=True,
                                  ensure_ascii=False) + "\n"
                with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                    f.write(line)
            else:
                self._memory.append(record)
            self._last_hash = record.hash_self
        return record

    def verify(self) -> tuple[bool, str]:
        records = self._read_all()
        if not records:
            return True, "empty audit log"
        for i, rec in enumerate(records):
            if rec.hash_self != rec.compute_hash():
                return False, f"entry {i}: hash mismatch (tampered)"
            if i == 0:
                if rec.hash_prev:
                    return False, "entry 0: hash_prev should be empty"
            elif rec.hash_prev != records[i - 1].hash_self:
                return False, f"entry {i}: chain broken (prev hash mismatch)"
        return True, f"chain intact: {len(records)} entries verified"

    def tail(self, n: int = 50) -> list[AuditRecord]:
        records = self._read_all()
        return records[-n:]

    # ── internals ──────────────────────────────────────────────

    def _read_all(self) -> list[AuditRecord]:
        if not self.path:
            return list(self._memory)
        if not self.path.exists():
            return []
        records: list[AuditRecord] = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(AuditRecord(**json.loads(line)))
                except (json.JSONDecodeError, TypeError):
                    continue  # unreadable lines fail verify() via truncation
        return records

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
