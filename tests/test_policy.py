"""Policy DSL: matching, effects, loading."""
import json

import pytest

from dvarapala import ActionIntent, ActionType, Policy, RiskLevel
from dvarapala.policy import Decision


def intent(tool="refund", risk=None, desc="", details=None):
    return ActionIntent(tool=tool, action_type=ActionType.DISPATCH_TOOL,
                        description=desc, details=details or {},
                        risk_level=risk)


def test_tool_glob_case_insensitive():
    p = Policy.from_dict({"rules": [
        {"id": "w", "match": {"tool": "write_*"}, "effect": "confirm"}]})
    assert p.decide(intent("WRITE_config"), RiskLevel.MEDIUM).effect == "confirm"
    assert p.decide(intent("read_file"), RiskLevel.LOW).effect == "default"


def test_first_matching_rule_wins():
    p = Policy.from_dict({"rules": [
        {"id": "first", "match": {"tool": "refund"}, "effect": "warn"},
        {"id": "second", "match": {"tool": "refund"}, "effect": "deny"}]})
    d = p.decide(intent("refund"), RiskLevel.HIGH)
    assert d.effect == "warn" and d.rule_id == "first"


def test_keyword_match():
    p = Policy.from_dict({"rules": [
        {"id": "drop", "match": {"keywords": ["drop table"]}, "effect": "deny"}]})
    assert p.decide(intent(desc="run DROP TABLE users"), RiskLevel.MEDIUM).effect == "deny"
    assert p.decide(intent(desc="select 1"), RiskLevel.MEDIUM).effect == "default"


def test_min_risk_boundary():
    p = Policy.from_dict({"rules": [
        {"id": "hi", "match": {"min_risk": "high"}, "effect": "confirm"}]})
    assert p.decide(intent(), RiskLevel.HIGH).effect == "confirm"
    assert p.decide(intent(), RiskLevel.CRITICAL).effect == "confirm"
    assert p.decide(intent(), RiskLevel.MEDIUM).effect == "default"


def test_combined_match_is_and():
    p = Policy.from_dict({"rules": [
        {"id": "both", "match": {"tool": "deploy_*", "min_risk": "medium"},
         "effect": "confirm"}]})
    assert p.decide(intent("deploy_web"), RiskLevel.MEDIUM).effect == "confirm"
    assert p.decide(intent("deploy_web"), RiskLevel.LOW).effect == "default"
    assert p.decide(intent("read_file"), RiskLevel.MEDIUM).effect == "default"


def test_invalid_effect_rejected():
    with pytest.raises(ValueError):
        Policy.from_dict({"rules": [{"id": "x", "match": {}, "effect": "maybe"}]})


def test_load_from_json_file(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"rules": [
        {"id": "deny-all-tools", "match": {"action_type": "dispatch_tool"},
         "effect": "deny"}]}), encoding="utf-8")
    p = Policy.load(path)
    assert p.decide(intent("anything"), RiskLevel.LOW).effect == "deny"


def test_empty_policy_defaults_to_consent_flow():
    p = Policy.from_dict({})
    assert p.decide(intent(), RiskLevel.MEDIUM) == Decision()
