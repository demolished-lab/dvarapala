"""Production-hardening features of the Gate."""
import json
import time

import pytest

from dvarapala import ApprovalResponse, ConsentLevel, Denied, Gate
from dvarapala.confirmer import AutoApprove, DenyAll
from dvarapala.risk import assess_command


class Always:
    def confirm(self, request):
        return ApprovalResponse(True, ConsentLevel.ALWAYS, "granted")


# ── per-tool rate limits ────────────────────────────────────────

def test_tool_rate_limits_are_per_pattern():
    gate = Gate(confirmer=AutoApprove("t"),
                tool_rate_limits={"deploy_*": (2, 60.0)})

    @gate(tool="deploy_app")
    def deploy_a():
        return "ok"

    @gate(tool="other_thing")
    def other():
        return "ok"

    assert deploy_a() == "ok"
    assert deploy_a() == "ok"
    with pytest.raises(Denied):
        deploy_a()
    assert other() == "ok"  # unaffected by the deploy_* budget


# ── consent persistence ─────────────────────────────────────────

def test_always_consent_survives_gate_restart(tmp_path):
    store = tmp_path / "consents.json"

    def make():
        return Gate(confirmer=Always(), consent_store=store,
                    auto_approve_low=False)

    calls = []

    @make()(tool="refund")
    def refund1():
        calls.append(1)
        return "done"

    assert refund1() == "done"          # prompts once, answers ALWAYS

    gate2 = make()

    @gate2(tool="refund")
    def refund2():
        calls.append(1)
        return "done"

    assert refund2() == "done"          # no confirmer consulted (store hit)
    data = json.loads(store.read_text(encoding="utf-8"))
    assert any(k.endswith("refund") for k in data["always"])


def test_clear_all_consents_wipes_store(tmp_path):
    store = tmp_path / "consents.json"
    gate = Gate(confirmer=Always(), consent_store=store, auto_approve_low=False)

    @gate(tool="wipe_me")
    def w():
        return 1

    w()
    assert store.exists()
    gate.clear_all_consents()
    assert not store.exists()


def test_session_consent_not_persisted(tmp_path):
    store = tmp_path / "consents.json"

    class SessionYes:
        def confirm(self, request):
            return ApprovalResponse(True, ConsentLevel.SESSION,
                                    "this run only")

    gate = Gate(confirmer=SessionYes(), consent_store=store,
                auto_approve_low=False)

    @gate(tool="once_only")
    def f():
        return 1

    assert f() == 1
    assert not store.exists()


# ── policy hot reload ───────────────────────────────────────────

def test_policy_hot_reload(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({
        "rules": [{"id": "allow-all", "match": {"tool": "*"},
                   "effect": "allow"}]
    }), encoding="utf-8")
    gate = Gate(policy=policy_path, confirmer=AutoApprove("t"))

    @gate()
    def anything():
        return "ran"

    assert anything() == "ran"

    policy_path.write_text(json.dumps({
        "rules": [{"id": "deny-all", "match": {"tool": "*"},
                   "effect": "deny", "message": "locked down"}]
    }), encoding="utf-8")
    os_utime(policy_path)

    with pytest.raises(Denied) as e:
        anything()
    assert "locked down" in str(e.value)


def os_utime(path):
    future = time.time() + 5
    import os
    os.utime(path, (future, future))


def test_broken_policy_edit_keeps_old_rules(tmp_path):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({
        "rules": [{"id": "allow", "match": {"tool": "*"}, "effect": "allow"}]
    }), encoding="utf-8")
    gate = Gate(policy=policy_path, confirmer=AutoApprove("t"))

    @gate()
    def f():
        return 1

    assert f() == 1
    policy_path.write_text("{not valid json", encoding="utf-8")
    os_utime(policy_path)
    assert f() == 1  # reload fails silently; previous rules still active


def test_explicit_policy_allow_skips_consent_for_any_risk():
    gate = Gate(confirmer=DenyAll("must not be consulted"),
                policy={"rules": [
                    {"id": "free", "match": {"tool": "search"},
                     "effect": "allow"}]})

    @gate(tool="search")
    def search(q):
        return [q]

    assert search("x") == ["x"]


# ── risk normalization hardening ────────────────────────────────

def test_ifs_expansion_caught_as_critical():
    assert assess_command("rm$IFS-rf /") is not None
    from dvarapala.intent import RiskLevel
    assert assess_command("rm$IFS-rf /") in (RiskLevel.CRITICAL,)
    assert assess_command("${IFS}rm -rf /") == RiskLevel.CRITICAL


def test_whitespace_evasion_normalized():
    from dvarapala.intent import RiskLevel
    assert assess_command("rm\t-rf /\n") == RiskLevel.CRITICAL


def test_confirm_no_longer_trips_rm_token():
    from dvarapala.intent import RiskLevel
    assert assess_command("confirm the deployment") != RiskLevel.CRITICAL


def test_leading_env_assignment_still_assessed():
    from dvarapala.intent import RiskLevel
    assert assess_command("FOO=bar rm -rf /") == RiskLevel.CRITICAL


def test_read_tokens_need_exact_first_word():
    from dvarapala.intent import RiskLevel
    assert assess_command("cat file.txt") == RiskLevel.LOW
    assert assess_command("catchphrases about cats") == RiskLevel.MEDIUM
