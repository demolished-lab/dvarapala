"""Redaction: secrets/PII scrubbed at the audit boundary."""
import json

from dvarapala import Gate
from dvarapala.confirmer import AutoApprove
from dvarapala.redact import Redactor, resolve_redactor

KEY = "sk-proj-abcdef12345678901234"
JWT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
       ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
       ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")


def test_secrets_level_scrubs_credentials():
    r = Redactor("secrets")
    out = r.text(f"use {KEY} and Bearer abcdefghijklmnopqrstuvwxyz123 then {JWT}")
    assert KEY not in out
    assert JWT not in out
    assert "[REDACTED]" in out


def test_secrets_level_leaves_emails_alone():
    out = Redactor("secrets").text("mail bob@corp.example about order 42")
    assert "bob@corp.example" in out


def test_strict_redacts_email_and_valid_cards():
    r = Redactor("strict")
    out = r.text("bob@corp.example paid with 4111 1111 1111 1111")
    assert "bob@corp.example" not in out
    assert "4111" not in out


def test_luhn_rejects_random_digit_runs():
    out = Redactor("strict").text("ticket 1234567890123 stays visible")
    assert "1234567890123" in out  # fails Luhn → not a card


def test_disabled_redactor_passthrough():
    r = resolve_redactor(None)
    assert not r.enabled
    assert r.text(KEY) == KEY


def test_unknown_level_raises():
    try:
        Redactor("nope")
        raise AssertionError("should have raised")
    except ValueError:
        pass


def test_gate_redacts_args_and_results_in_audit(tmp_path):

    audit = tmp_path / "a.jsonl"
    gate = Gate(confirmer=AutoApprove("ok"), audit=str(audit))

    @gate(risk="low", tool="echo_token")
    def echo_token(token):
        return f"token={token}"

    assert echo_token(KEY) == f"token={KEY}"
    recs = gate.tail(10)
    assert recs
    for r in recs:
        blob = json.dumps(r.payload())
        assert KEY not in blob, f"secret leaked into record: {blob[:200]}"


def test_gate_redaction_can_be_disabled(tmp_path):
    audit = tmp_path / "b.jsonl"
    gate = Gate(confirmer=AutoApprove("ok"), audit=str(audit), redact=None)

    @gate(risk="low", tool="echo_plain")
    def echo_plain(word):
        return word

    assert echo_plain("visible-arg") == "visible-arg"
    blob = "".join(json.dumps(r.payload()) for r in gate.tail(10))
    assert "visible-arg" in blob
