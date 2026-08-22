"""Pluggable confirmation backends.

A confirmer is any object with ``confirm(request) -> ApprovalResponse``
(sync or async). Ship three:

- :class:`CLIConfirmer` — interactive stdin prompt (y/N/s/a)
- :class:`AutoApprove`  — approve everything (dev/demo; audit still written)
- :class:`DenyAll`      — refuse everything (headless-safe default)
"""
from __future__ import annotations

import sys
from typing import ClassVar

from .intent import ApprovalRequest, ApprovalResponse, ConsentLevel, RiskLevel


class CLIConfirmer:
    """Interactive terminal prompt. Falls back to deny on EOF/Ctrl-C."""

    _ICONS: ClassVar[dict] = {RiskLevel.LOW: "", RiskLevel.MEDIUM: "[!] ",
                              RiskLevel.HIGH: "[!!] ",
                              RiskLevel.CRITICAL: "[!!!] "}

    def confirm(self, request: ApprovalRequest) -> ApprovalResponse:
        print()
        print(request.render())
        try:
            raw = input("Proceed? [y/N/s=session/a=always] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return ApprovalResponse(False, reason="cancelled")
        if raw == "y":
            return ApprovalResponse(True, ConsentLevel.ONCE)
        if raw == "s":
            return ApprovalResponse(True, ConsentLevel.SESSION,
                                    reason="approved for session")
        if raw == "a":
            return ApprovalResponse(True, ConsentLevel.ALWAYS,
                                    reason="approved always")
        return ApprovalResponse(False, reason="rejected by user")


class AutoApprove:
    """Approve every request once. For development and demos only."""

    def __init__(self, reason: str = "auto-approved"):
        self.reason = reason

    def confirm(self, request: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(True, ConsentLevel.ONCE, self.reason)


class DenyAll:
    """Refuse every request. Safe default for non-interactive contexts."""

    def __init__(self, reason: str = "denied by policy"):
        self.reason = reason

    def confirm(self, request: ApprovalRequest) -> ApprovalResponse:
        return ApprovalResponse(False, ConsentLevel.ONCE, self.reason)


def resolve_confirmer(spec: object) -> object:
    """Normalize the Gate(confirmer=...) argument."""
    if spec is None:
        if sys.stdin.isatty():
            return CLIConfirmer()
        return DenyAll("non-interactive session")
    if spec == "cli":
        return CLIConfirmer()
    if spec == "auto":
        return AutoApprove()
    if spec == "deny":
        return DenyAll()
    return spec
