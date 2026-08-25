"""Heuristic risk assessment for common action shapes.

Intentionally conservative: unknown commands default to MEDIUM,
destructive tokens escalate to CRITICAL. Callers can always override
with ``intent.risk_level``.

Commands are normalized before matching so trivial evasions (extra
whitespace, ``$IFS``, tabs/newlines, case) cannot slip a destructive
token past the classifier. This is defense-in-depth, not a parser —
policies remain the authoritative control.
"""
from __future__ import annotations

import re

from .intent import ActionIntent, ActionType, RiskLevel

_COMMAND_CRITICAL_SUBSTR = (
    "rm ", "del ", "rd ", "format ", "dd if=", "mkfs.", "chmod 777",
)
_COMMAND_CRITICAL_WORD = (
    "rmdir", "shutdown", "reboot", "poweroff", "halt", "fdisk", "chattr",
)
_COMMAND_HIGH_NONPIPE = (
    "git push", "git commit", "git merge", "git rebase", "git reset",
    "docker ", "podman ", "install ", "uninstall ", "chown ",
)
_COMMAND_PIPES = ("| sh", "| bash", "| pwsh")
_COMMAND_MEDIUM = ("curl ", "wget ", "fetch ")
_REDIRECT_TOKENS = ("> ", ">> ", "| tee")
_READ_FIRST_TOKENS = frozenset({
    "ls", "dir", "cat", "head", "tail", "wc", "find", "grep", "rg", "tree",
    "pwd", "echo", "type", "which", "where", "date", "whoami", "hostname",
    "ps", "df", "du", "free", "uname",
})
_READ_PREFIXES = (
    "git log", "git status", "git diff", "git branch",
    "pip list", "pip show", "npm list", "npm view",
    "python --version", "node --version", "pip --version",
)
_SYSTEM_PATH_MARKERS = ("/etc/", "/usr/", "/boot/", "/windows/",
                        "c:\\windows", "system32")

_EVASION_VARS = re.compile(r"\$\{?(ifs|path|shell)\}?")
_WHITESPACE = re.compile(r"[\s]+")
_LEADING_ENV = re.compile(r"^(?:\w+=[^\s]*\s+)+")


def _normalize(cmd: str) -> str:
    """Lowercase, expand common shell evasion variables, collapse
    whitespace, and strip leading env assignments so token checks see the
    effective command words."""
    low = cmd.strip().lower()
    low = _EVASION_VARS.sub(" ", low)
    low = _LEADING_ENV.sub("", low)
    low = _WHITESPACE.sub(" ", low)
    return low


def _padded_hit(tokens: tuple[str, ...], blob: str) -> bool:
    """Match tokens guarded by a preceding word boundary so fragments
    never fire ('confirm' cannot trip 'rm ', 'model' cannot trip 'del ')."""
    return any(f" {token}" in blob for token in tokens)


def assess_command(cmd: str) -> RiskLevel:
    """Assess the risk of a shell command string."""
    if not cmd or not cmd.strip():
        return RiskLevel.MEDIUM
    low = _normalize(cmd)
    blob = f" {low} "
    if any(token in low for token in _COMMAND_CRITICAL_WORD):
        return RiskLevel.CRITICAL
    if _padded_hit(_COMMAND_CRITICAL_SUBSTR, blob):
        return RiskLevel.CRITICAL
    if _padded_hit(_COMMAND_HIGH_NONPIPE, blob):
        return RiskLevel.HIGH
    if any(token in low for token in _COMMAND_PIPES):
        return RiskLevel.HIGH
    if _padded_hit(_COMMAND_MEDIUM, blob):
        return RiskLevel.MEDIUM
    if any(token in low for token in _REDIRECT_TOKENS):
        return RiskLevel.MEDIUM
    if _padded_hit(("touch ",), blob):
        return RiskLevel.MEDIUM
    for prefix in _READ_PREFIXES:
        if low.startswith(prefix):
            return RiskLevel.LOW
    first = low.split()[0] if low.split() else ""
    if first in _READ_FIRST_TOKENS:
        return RiskLevel.LOW
    return RiskLevel.MEDIUM


def assess(intent: ActionIntent) -> RiskLevel:
    """Return the risk level for an intent, respecting an explicit override."""
    if intent.risk_level is not None:
        return intent.risk_level

    at = intent.action_type

    if at == ActionType.EXECUTE_COMMAND:
        cmd = (intent.details.get("command")
               or intent.details.get("cmd") or "")
        return assess_command(str(cmd))

    if at == ActionType.WRITE_FILE:
        path = str(intent.details.get("path", ""))
        content = str(intent.details.get("content", ""))
        lowered = path.lower()
        if any(marker in lowered for marker in _SYSTEM_PATH_MARKERS):
            return RiskLevel.CRITICAL
        if len(content) > 1000:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    if at == ActionType.WEB_FETCH:
        return RiskLevel.LOW

    # DISPATCH_TOOL and CUSTOM: a tool call's blast radius is unknown here;
    # policies should classify important tools explicitly via min_risk rules.
    return RiskLevel.MEDIUM


def consent_key(intent: ActionIntent) -> str:
    """Cache key for remembered consent: coarse enough to be useful,
    specific enough to be safe (command name only, not full args)."""
    if intent.action_type == ActionType.EXECUTE_COMMAND:
        cmd = str(intent.details.get("command") or "").strip().lower()
        base = cmd.split()[0] if cmd.split() else cmd
        return f"cmd:{base}"
    return f"{intent.action_type.value}:{intent.tool}"
