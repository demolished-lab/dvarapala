"""Adversarial audit-log tests: truncation, torn lines, multi-process."""
import subprocess
import sys

from dvarapala.audit import AuditLog, AuditRecord


def rec(i: int) -> AuditRecord:
    return AuditRecord(timestamp=1000.0 + i, event="allowed", tool=f"t{i}",
                       action_type="dispatch_tool")


def test_truncated_tail_detected_when_anchored(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(10):
        log.append(rec(i))
    assert log.verify() == (True, log.verify()[1])

    raw = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(raw[:6]) + "\n", encoding="utf-8")

    ok, msg = AuditLog(path).verify()
    assert not ok
    assert "anchored head" in msg or "truncated" in msg


def test_tail_rewrite_detected_when_anchored(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(5):
        log.append(rec(i))

    lines = path.read_text(encoding="utf-8").splitlines()
    import json
    last = json.loads(lines[-1])
    last["decision_reason"] = "forged after the fact"
    lines[-1] = json.dumps(last)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, msg = AuditLog(path).verify()
    assert not ok
    assert "anchored head" in msg or "tampered" in msg


def test_verify_without_anchor_still_passes_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(3):
        log.append(rec(i))
    (tmp_path / "audit.jsonl.head").unlink()  # remove anchor
    ok, _ = AuditLog(path).verify(strict=False)
    assert ok


def test_strict_requires_anchor(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(rec(0))
    (tmp_path / "audit.jsonl.head").unlink()
    ok, msg = AuditLog(path).verify(strict=True)
    assert not ok and "no anchor" in msg


def test_torn_line_fails_verification(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(4):
        log.append(rec(i))
    raw = path.read_text(encoding="utf-8")
    lines = raw.splitlines()
    lines[1] = lines[1][:40]  # simulate a crash mid-write
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, msg = AuditLog(path).verify()
    assert not ok and "corrupt" in msg


def test_refresh_anchor_after_intentional_prune(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(8):
        log.append(rec(i))
    raw = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(raw[-2:]) + "\n", encoding="utf-8")
    ok, _ = AuditLog(path).verify(strict=True)
    assert not ok  # prune breaks the anchor until re-anchored

    tip = AuditLog(path).refresh_anchor()
    assert len(tip) == 64
    ok, _ = AuditLog(path).verify(strict=True)
    assert not ok  # pruned prefix still fails hash_prev of first kept row


_APPEND_CHILD = """
import sys
from dvarapala.audit import AuditLog, AuditRecord
path, n, tag = sys.argv[1], int(sys.argv[2]), sys.argv[3]
log = AuditLog(path)
for i in range(n):
    log.append(AuditRecord(timestamp=1.0, event="allowed",
                           tool="proc%s-%d" % (tag, i),
                           action_type="dispatch_tool"))
"""


def test_two_processes_can_share_one_log(tmp_path):
    path = str(tmp_path / "shared.jsonl")
    procs = [
        subprocess.Popen([sys.executable, "-c", _APPEND_CHILD, path, "15",
                          str(pid)])
        for pid in range(2)
    ]
    codes = [p.wait(timeout=60) for p in procs]
    assert codes == [0, 0]

    log = AuditLog(path)
    records = log.tail(10_000)
    assert len(records) == 30
    ok, msg = log.verify(strict=True)
    assert ok, msg
    assert len({r.tool for r in records}) == 30
