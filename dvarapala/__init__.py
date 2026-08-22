"""Dvarapala (द्वारपाल) — the door guardian.

Permission gates, consent levels, and tamper-evident audit logs for
AI agents and MCP servers. Stdlib-only core; MIT licensed.
"""
from .audit import SCHEMA_VERSION, AuditLog, AuditRecord
from .confirmer import (
    AutoApprove,
    CLIConfirmer,
    DenyAll,
    resolve_confirmer,
)
from .gate import CausalInfo, Denied, Gate, step
from .intent import (
    ActionIntent,
    ActionType,
    ApprovalRequest,
    ApprovalResponse,
    ConsentLevel,
    RiskLevel,
)
from .policy import Decision, Policy, Rule

__version__ = "0.1.0"

__all__ = [
    "SCHEMA_VERSION",
    "ActionIntent",
    "ActionType",
    "ApprovalRequest",
    "ApprovalResponse",
    "AuditLog",
    "AuditRecord",
    "AutoApprove",
    "CLIConfirmer",
    "CausalInfo",
    "ConsentLevel",
    "Decision",
    "Denied",
    "DenyAll",
    "Gate",
    "Policy",
    "RiskLevel",
    "Rule",
    "resolve_confirmer",
    "step",
]
