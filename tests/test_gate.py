"""Gate pipeline: policy, consent caching, kill switch, rate limit, causal ctx."""
import asyncio

import pytest

import dvarapala
from dvarapala import AutoApprove, Denied, DenyAll, Gate
from dvarapala import step as dva_step
from dvarapala.confirmer import CLIConfirmer


def make_gate(**kw):
    kw.setdefault("confirmer", AutoApprove("test"))
    return Gate(**kw)


class ScriptedConfirmer:
    """Returns queued responses; counts how many times it was consulted."""

    def __init__(self, *responses):
        self.queue = list(responses)
        self.calls = 0

    def confirm(self, request):
        self.calls += 1
        return self.queue.pop(0) if self.queue else DenyAll().confirm(request)


# ── decorator basics ────────────────────────────────────────────

def test_low_risk_auto_approved_without_confirmer():
    gate = make_gate(confirmer=DenyAll("should not be consulted"))
    ran = []

    @gate(risk="low")
    def read_file(path):
        ran.append(path)
        return "data"

    assert read_file("/tmp/x") == "data"
    assert ran == ["/tmp/x"]


def test_unknown_tool_defaults_to_medium_and_asks():
    """Deny-safe default: unclassified tools require consent."""
    gate = make_gate(confirmer=DenyAll("unclassified"))

    @gate()
    def mystery(x):
        return x

    with pytest.raises(Denied):
        mystery(1)
    assert gate.tail(1)[0].risk == "medium"


def test_policy_deny_raises_and_skips_function():
    gate = make_gate(policy={
        "rules": [{"id": "no-refunds", "match": {"tool": "refund"},
                   "effect": "deny", "message": "refunds disabled"}]
    })
    ran = []

    @gate(risk="critical")
    def refund(cid, cents):
        ran.append((cid, cents))
        return "ok"

    with pytest.raises(Denied) as excinfo:
        refund("c1", 500)
    assert excinfo.value.rule_id == "no-refunds"
    assert "refunds disabled" in str(excinfo.value)
    assert ran == []


def test_confirmation_and_session_caching():
    conf = ScriptedConfirmer(
        dvarapala.ApprovalResponse(True, dvarapala.ConsentLevel.SESSION,
                                   "ok this time"))
    gate = make_gate(confirmer=conf,
                     policy={"rules": [
                         {"id": "confirm-writes",
                          "match": {"tool": "write_*"}, "effect": "confirm"}]})
    calls = []

    @gate(tool="write_config")
    def write_config():
        calls.append(1)
        return "written"

    assert write_config() == "written"
    assert write_config() == "written"      # second call: session consent hit
    assert len(calls) == 2
    assert conf.calls == 1                  # confirmer consulted only once


def test_denial_records_audit_event():
    gate = make_gate(confirmer=DenyAll("user said no"))

    @gate(risk="high")
    def dangerous():
        return "never"

    with pytest.raises(Denied):
        dangerous()

    recs = gate.tail(5)
    denied = [r for r in recs if r.event == "denied"]
    assert denied and "user said no" in denied[-1].decision_reason


def test_outcome_recorded_after_execution():
    gate = make_gate()

    @gate()
    def add(a, b):
        return a + b

    assert add(2, 3) == 5
    recs = gate.tail(10)
    executed = [r for r in recs if r.event == "executed"]
    assert executed and "5" in executed[-1].state_delta


def test_failure_recorded_then_reraised():
    gate = make_gate()

    @gate()
    def boom():
        raise ValueError("kaboom")

    with pytest.raises(ValueError):
        boom()
    failed = [r for r in gate.tail(10) if r.event == "failed"]
    assert failed and "ValueError" in failed[-1].error


# ── safety hardware ─────────────────────────────────────────────

def test_kill_switch_blocks_everything(tmp_path):
    ks = tmp_path / "killswitch"
    gate = make_gate(kill_switch_path=ks)

    @gate()
    def anything():
        return "ran"

    assert anything() == "ran"              # switch off → fine
    gate.engage_kill_switch("incident")
    with pytest.raises(Denied):
        anything()
    gate.release_kill_switch()
    assert anything() == "ran"


def test_rate_limit(tmp_path):
    gate = make_gate(rate_limit=(2, 60.0))

    @gate()
    def ping():
        return "pong"

    assert ping() == "pong"
    assert ping() == "pong"
    with pytest.raises(Denied):
        ping()


# ── causal context ──────────────────────────────────────────────

def test_step_context_lands_in_audit_record():
    gate = make_gate()

    @gate()
    def refund(cid):
        return "done"

    with dva_step(run_id="run_abc", step_no=17, parent_step=6,
                  alternatives_considered=["cancel_order"],
                  context_refs=["ticket:991"]):
        refund("c1")

    rec = [r for r in gate.tail(10) if r.event == "executed"][-1]
    assert rec.run_id == "run_abc"
    assert rec.step == 17
    assert rec.parent_step == 6
    assert rec.alternatives_considered == ["cancel_order"]
    assert rec.context_refs == ["ticket:991"]


def test_async_function_support():
    gate = make_gate()

    @gate(risk="low")
    async def fetch(url):
        return f"got {url}"

    assert asyncio.run(fetch("http://x")) == "got http://x"


def test_async_denied():
    from dvarapala.intent import ApprovalResponse, ConsentLevel

    class No:
        def confirm(self, request):
            return ApprovalResponse(False, ConsentLevel.ONCE, "nope")

    gate = Gate(confirmer=No(),
                policy={"rules": [
                    {"id": "c", "match": {"tool": "deploy"},
                     "effect": "confirm"}]})

    @gate(tool="deploy")
    async def deploy():
        return "deployed"

    with pytest.raises(Denied):
        asyncio.run(deploy())


def test_cli_confirmer_parsing(monkeypatch):
    conf = CLIConfirmer()
    monkeypatch.setattr("builtins.input", lambda _: "y")
    gate = make_gate(confirmer=conf)

    @gate(risk="high")
    def risky():
        return "ok"

    assert risky() == "ok"
