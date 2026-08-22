"""Hash-chain integrity of the audit log."""
import json

from dvarapala.audit import AuditLog, AuditRecord


def make_rec(event="allowed", tool="t1"):
    import time
    return AuditRecord(timestamp=time.time(), event=event, tool=tool,
                       action_type="dispatch_tool", risk="low")


def test_chain_roundtrip_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for ev in ("allowed", "denied", "executed"):
        log.append(make_rec(event=ev))

    ok, msg = log.verify()
    assert ok, msg
    assert "3 entries" in msg


def test_tampering_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(make_rec(tool="t1"))
    log.append(make_rec(tool="t2"))
    log.append(make_rec(tool="t3"))

    lines = path.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["tool"] = "FORGED"          # attacker edits history
    lines[1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, msg = AuditLog(path).verify()
    assert not ok
    assert "tampered" in msg or "mismatch" in msg


def test_deletion_breaks_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(make_rec(tool="t1"))
    log.append(make_rec(tool="t2"))
    log.append(make_rec(tool="t3"))

    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[0]                    # attacker deletes first entry
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, _msg = AuditLog(path).verify()
    assert not ok


def test_memory_mode():
    log = AuditLog()
    log.append(make_rec())
    log.append(make_rec())
    assert len(log.tail(10)) == 2
    ok, _ = log.verify()
    assert ok


def test_resume_existing_log(tmp_path):
    """A new process must continue the chain from disk."""
    path = tmp_path / "audit.jsonl"
    AuditLog(path).append(make_rec())
    fresh = AuditLog(path)          # simulates restart
    fresh.append(make_rec())
    ok, msg = fresh.verify()
    assert ok, msg
