"""Heuristic risk assessment for common action shapes.

Ported from battle-tested heuristics; intentionally conservative:
unknown commands default to MEDIUM, destructive tokens escalate to
CRITICAL. Callers can always override with ``intent.risk_level``.
"""
from __future__ import annotations

from .intent import ActionIntent, ActionType, RiskLevel

_COMMAND_CRITICAL = (
    "rm ", "rmdir", "del ", "rd ", "format ", "dd if=", "mkfs.", "fdisk",
    "shutdown", "reboot", "poweroff", "halt", "chmod 777", "chattr",
)
_COMMAND_HIGH = (
    "git push", "git commit", "git merge", "git rebase", "git reset",
    "docker ", "podman ", "install ", "uninstall ", "chown ",
    "| sh", "| bash", "| pwsh",
)
_COMMAND_MEDIUM = ("curl ", "wget ", "fetch ")
_WRITE_TOKENS = ("> ", ">> ", "| tee", "touch ")
_READ_PREFIXES = (
    "ls", "dir", "cat", "head", "tail", "wc", "find", "grep", "rg", "tree",
    "pwd", "echo", "type", "which", "where", "git log", "git status",
    "git diff", "git branch", "pip list", "pip show", "npm list", "npm view",
    "date", "whoami", "hostname", "ps ", "df ", "du ", "free ", "uname",
    "python --version", "node --version", "pip --version",
)
_SYSTEM_PATH_MARKERS = ("/etc/", "/usr/", "/boot/", "/windows/",
                        "c:\\windows", "system32")


def assess_command(cmd: str) -> RiskLevel:
    """Assess the risk of a shell command string."""
    if not cmd:
        return RiskLevel.MEDIUM
    low = cmd.strip().lower()
    for token in _COMMAND_CRITICAL:
        if token in low:
            return RiskLevel.CRITICAL
    for token in _COMMAND_HIGH:
        if token in low:
            return RiskLevel.HIGH
    for token in _COMMAND_MEDIUM:
        if token in low:
            return RiskLevel.MEDIUM
    for token in _WRITE_TOKENS:
        if token in low:
            return RiskLevel.MEDIUM
    for prefix in _READ_PREFIXES:
        if low.startswith(prefix):
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
