"""Redact secrets and PII before they reach the audit log.

The audit log is evidence — but it is also a file on disk. Writing raw
arguments and results means API keys, bearer tokens, and customer emails
end up in plaintext history. The redactor scrubs known secret shapes at
the audit boundary (policy matching and human approval previews still see
the real values).

Levels:

- ``"secrets"`` (default) — high-confidence credential patterns only.
- ``"strict"`` — secrets + emails + credit cards (Luhn-checked).
- ``None`` — disabled.
- A list of pattern names selects a custom set.
"""
from __future__ import annotations

import re
from collections.abc import Callable

SECRETS_PATTERNS: dict[str, str] = {
    "aws_key": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "openai_sk": r"\bsk-[A-Za-z0-9_-]{20,}\b",
    "github_pat": r"\bgh[pousr]_[A-Za-z0-9]{30,}\b",
    "slack_token": r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b",
    "google_api": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "jwt": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b",
    "bearer": r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{18,}=*",
    "private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "password_kv": r"(?i)\b(password|passwd|secret|api_?key|token)\s*[=:]\s*\S+",
}

STRICT_EXTRA: dict[str, str] = {
    "email": r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b",
}


def _luhn_match(m: re.Match[str]) -> str:
    digits = [int(c) for c in re.sub(r"\D", "", m.group(0))]
    if 13 <= len(digits) <= 19:
        checksum = 0
        parity = len(digits) % 2
        for i, d in enumerate(digits):
            if i % 2 == parity:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        if checksum % 10 == 0:
            return "[REDACTED]"
    return m.group(0)


CREDIT_CARD = (r"\b(?:\d[ -]?){13,19}\b", _luhn_match)

_REPLACEMENT = "[REDACTED]"


class Redactor:
    """Compile named regex patterns; scrub text with them."""

    def __init__(self, level: str | list[str] | None = "secrets",
                 replacement: str = _REPLACEMENT):
        self.replacement = replacement
        self._rules: list[tuple[str, re.Pattern[str], Callable | None]] = []
        if level is None:
            return
        if isinstance(level, str):
            if level == "secrets":
                names: list[str] = list(SECRETS_PATTERNS)
            elif level == "strict":
                names = (list(SECRETS_PATTERNS) + list(STRICT_EXTRA)
                         + ["credit_card"])
            else:
                raise ValueError(
                    f"unknown redaction level: {level!r} "
                    "(use 'secrets', 'strict', None, or a name list)")
        else:
            names = list(level)
        for name in names:
            if name == "credit_card":
                pat, fn = CREDIT_CARD
                self._rules.append((name, re.compile(pat), fn))
            elif name in SECRETS_PATTERNS:
                self._rules.append((name, re.compile(SECRETS_PATTERNS[name]),
                                    None))
            elif name in STRICT_EXTRA:
                self._rules.append((name, re.compile(STRICT_EXTRA[name]), None))
            else:
                raise ValueError(f"unknown redaction pattern: {name!r}")

    @property
    def enabled(self) -> bool:
        return bool(self._rules)

    def text(self, value: str) -> str:
        for _, rx, fn in self._rules:
            value = rx.sub(fn or self.replacement, value)
        return value

    def names(self) -> list[str]:
        return [n for n, _, _ in self._rules]


def resolve_redactor(spec: str | list[str] | Redactor | None) -> Redactor:
    if isinstance(spec, Redactor):
        return spec
    return Redactor(spec)
