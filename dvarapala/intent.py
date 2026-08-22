"""Action intents, risk levels, and consent levels.

An :class:`ActionIntent` describes what an agent *wants* to do, before it
happens. It carries causal fields so the surrounding harness can record
where in a run the decision was made.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class StrEnum(str, Enum):
    """``str``-backed Enum compatible with Python 3.10 (enum.StrEnum is 3.11+)."""

    def __str__(self) -> str:
        return self.value


class ActionType(StrEnum):
    EXECUTE_COMMAND = "execute_command"
    WRITE_FILE = "write_file"
    WEB_FETCH = "web_fetch"
    DISPATCH_TOOL = "dispatch_tool"  # any agent / MCP tool call
    CUSTOM = "custom"


class RiskLevel(StrEnum):
    LOW = "low"            # read-only; auto-approved by default
    MEDIUM = "medium"      # needs consent (or policy override)
    HIGH = "high"          # explicit confirmation recommended
    CRITICAL = "critical"  # destructive/irreversible


class ConsentLevel(StrEnum):
    ONCE = "once"          # ask every time
    SESSION = "session"    # remember for this process
    ALWAYS = "always"      # never ask again for this tool


@dataclass
class ActionIntent:
    """A planned action, submitted to the gate before execution."""

    tool: str = ""
    action_type: ActionType = ActionType.DISPATCH_TOOL
    description: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    diff_preview: str = ""       # short human-readable preview of the change
    risk_level: RiskLevel | None = None  # None → assessed heuristically
    source: str = ""             # agent/framework name

    # Causal fields — fill via dvarapala.step(...) or directly.
    run_id: str = ""
    step: int | None = None
    parent_step: int | None = None
    context_refs: list[str] = field(default_factory=list)
    alternatives_considered: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.run_id:
            self.run_id = f"run_{uuid.uuid4().hex[:12]}"
        if not self.description and self.tool:
            self.description = self.tool


@dataclass
class ApprovalRequest:
    """What a confirmer backend sees when human consent is needed."""

    intent: ActionIntent
    risk: RiskLevel
    rule_id: str | None = None
    message: str = ""

    def render(self) -> str:
        icons = {RiskLevel.LOW: "", RiskLevel.MEDIUM: "[!] ",
                 RiskLevel.HIGH: "[!!] ", RiskLevel.CRITICAL: "[!!!] "}
        lines = [
            "=" * 60,
            f"{icons.get(self.risk, '')}Approval required"
            + (f" ({self.message})" if self.message else ""),
            f"  Tool:   {self.intent.tool}",
            f"  Type:   {self.intent.action_type}",
            f"  Risk:   {self.risk}",
        ]
        if self.intent.source:
            lines.append(f"  Source: {self.intent.source}")
        if self.intent.diff_preview:
            lines.append("  Preview:")
            for ln in self.intent.diff_preview.splitlines()[:8]:
                lines.append(f"    {ln}")
        lines.append("=" * 60)
        return "\n".join(lines)


@dataclass
class ApprovalResponse:
    approved: bool
    consent: ConsentLevel = ConsentLevel.ONCE
    reason: str = ""
    responded_at: float = field(default_factory=time.time)
