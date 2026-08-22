"""Declarative policy rules evaluated before consent is requested.

A policy is an ordered rule list; the first matching rule wins.

Match keys (all optional, ANDed together):
  tool        fnmatch glob against intent.tool (case-insensitive)
  action_type exact ActionType value
  keywords    list of case-insensitive substrings matched against the
              description + diff preview + details JSON
  min_risk    match when assessed risk is at or above this level

Effects:
  allow    skip confirmation entirely
  warn     log a warning, then continue through normal consent
  confirm  require confirmation even for low-risk actions
  deny     refuse immediately (raises dvarapala.Denied in decorators)

Policies load from a dict or a JSON file. YAML works too if ``pyyaml``
is installed (``pip install dvarapala[yaml]``).
"""
from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .intent import ActionIntent, RiskLevel

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
VALID_EFFECTS = {"allow", "warn", "confirm", "deny"}


@dataclass(frozen=True)
class Decision:
    effect: str = "default"  # "default" → fall through to risk-based consent
    rule_id: str | None = None
    message: str = ""


@dataclass
class Rule:
    id: str
    effect: str
    match: dict[str, Any] = field(default_factory=dict)
    message: str = ""


class Policy:
    def __init__(self, data: dict[str, Any]):
        defaults = data.get("defaults", {})
        self.on_no_match: str = defaults.get("on_no_match", "default")
        if self.on_no_match not in VALID_EFFECTS | {"default"}:
            raise ValueError(f"invalid on_no_match effect: {self.on_no_match!r}")
        self.rules: list[Rule] = []
        for raw in data.get("rules", []):
            effect = raw.get("effect")
            if effect not in VALID_EFFECTS:
                raise ValueError(f"rule {raw.get('id', '?')!r}: "
                                 f"invalid effect {effect!r}")
            self.rules.append(Rule(
                id=raw.get("id", f"rule_{len(self.rules)}"),
                effect=effect,
                match=raw.get("match", {}),
                message=raw.get("message", ""),
            ))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        return cls(data)

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        path = Path(path)
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore[import-untyped]
            except ImportError as exc:
                raise ImportError(
                    "install pyyaml to load YAML policies: "
                    "pip install dvarapala[yaml]") from exc
            return cls(yaml.safe_load(text) or {})
        return cls(json.loads(text))

    def decide(self, intent: ActionIntent, risk: RiskLevel) -> Decision:
        for rule in self.rules:
            if _matches(rule, intent, risk):
                return Decision(effect=rule.effect, rule_id=rule.id,
                                message=rule.message)
        return Decision(effect=self.on_no_match)


def _matches(rule: Rule, intent: ActionIntent, risk: RiskLevel) -> bool:
    m = rule.match or {}

    tool_glob = m.get("tool")
    if tool_glob is not None and not fnmatch.fnmatch(
            intent.tool.lower(), str(tool_glob).lower()):
        return False

    action_type = m.get("action_type")
    if action_type is not None and intent.action_type.value != action_type:
        return False

    keywords = m.get("keywords")
    if keywords:
        blob = " ".join([
            intent.description,
            intent.diff_preview,
            json.dumps(intent.details, default=str)[:2000],
        ]).lower()
        if not any(str(k).lower() in blob for k in keywords):
            return False

    min_risk = m.get("min_risk")
    if min_risk is not None:
        floor = RISK_ORDER.get(str(min_risk))
        if floor is None:
            raise ValueError(f"invalid min_risk: {min_risk!r}")
        if RISK_ORDER.get(risk.value, 1) < floor:
            return False

    return True
