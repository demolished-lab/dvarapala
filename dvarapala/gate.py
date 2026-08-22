"""The gate: policy → risk → consent → tamper-evident audit.

Usage as a decorator::

    import dvarapala

    gate = dvarapala.Gate(policy="policy.json", audit="audit.jsonl")

    @gate(risk="critical")
    def refund(customer_id: str, amount_cents: int): ...

    refund("c1", 500)   # runs only if policy+consent approve; else raises Denied

Causal context is captured with :func:`step` so every audit record knows
where in the agent run it happened::

    with dvarapala.step(run_id="r1", step=17, alternatives=["cancel_order"]):
        refund("c1", 500)
"""
from __future__ import annotations

import functools
import inspect
import json
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditLog, AuditRecord
from .confirmer import resolve_confirmer
from .intent import (
    ActionIntent,
    ActionType,
    ApprovalRequest,
    ApprovalResponse,
    ConsentLevel,
    RiskLevel,
)
from .policy import Policy
from .risk import assess, consent_key

__all__ = ["CausalInfo", "Denied", "Gate", "step"]


class Denied(PermissionError):
    """Raised when a gated call is not approved."""

    def __init__(self, message: str, *, rule_id: str | None = None,
                 record: AuditRecord | None = None):
        super().__init__(message)
        self.rule_id = rule_id
        self.record = record


@dataclass(frozen=True)
class CausalInfo:
    run_id: str = ""
    step: int | None = None
    parent_step: int | None = None
    context_refs: tuple[str, ...] = ()
    alternatives_considered: tuple[str, ...] = ()


_CAUSAL: ContextVar[CausalInfo | None] = ContextVar("dvarapala_causal",
                                                    default=None)


@contextmanager
def step(run_id: str = "", step_no: int | None = None,
         parent_step: int | None = None,
         context_refs: list[str] | None = None,
         alternatives_considered: list[str] | None = None):
    """Annotate every gated call inside this block with causal metadata."""
    info = CausalInfo(
        run_id=run_id,
        step=step_no,
        parent_step=parent_step,
        context_refs=tuple(context_refs or ()),
        alternatives_considered=tuple(alternatives_considered or ()),
    )
    token = _CAUSAL.set(info)
    try:
        yield info
    finally:
        _CAUSAL.reset(token)


def _snapshot(fn: Callable, args: tuple, kwargs: dict) -> dict[str, Any]:
    """Capture call arguments compactly for the audit record."""
    try:
        bound = inspect.signature(fn).bind(*args, **kwargs)
        items = [(str(k), v) for k, v in bound.arguments.items()]
    except (TypeError, ValueError):
        items = [("", v) for v in args] + list(kwargs.items())

    def short(v: Any) -> str:
        text = repr(v)
        return text if len(text) <= 200 else text[:197] + "..."

    snap = {k or f"arg{i}": short(v) for i, (k, v) in enumerate(items)}
    out = json.dumps(snap, default=str)
    return {"args": out[:1000]}


class Gate:
    """Central permission gate. One instance per app/agent is typical."""

    def __init__(self,
                 policy: Policy | dict | str | Path | None = None,
                 audit: AuditLog | str | Path | None = None,
                 confirmer: object | str | None = None,
                 *,
                 source: str = "",
                 auto_approve_low: bool = True,
                 rate_limit: tuple[int, float] | None = None,
                 kill_switch_path: str | Path | None = None):
        if isinstance(policy, Policy):
            self.policy = policy
        elif isinstance(policy, dict):
            self.policy = Policy.from_dict(policy)
        elif isinstance(policy, (str, Path)):
            self.policy = Policy.load(policy)
        else:
            self.policy = Policy.from_dict({})

        if isinstance(audit, AuditLog):
            self.audit = audit
        elif isinstance(audit, (str, Path)):
            self.audit = AuditLog(audit)
        else:
            self.audit = AuditLog()

        self.confirmer = resolve_confirmer(confirmer)
        self.source = source
        self.auto_approve_low = auto_approve_low
        self.rate_limit = rate_limit
        self.kill_switch_path = Path(kill_switch_path) if kill_switch_path else None

        self._consents: dict[str, ConsentLevel] = {}
        self._rl_timestamps: list[float] = []
        self._lock = threading.Lock()

    # ── public API ─────────────────────────────────────────────

    def check(self, intent: ActionIntent) -> tuple[bool, AuditRecord]:
        """Run the full pipeline on an intent without executing anything."""
        self._apply_causal(intent)

        record = AuditRecord(
            timestamp=time.time(),
            event="allowed",
            tool=intent.tool,
            action_type=intent.action_type.value,
            source=self.source or intent.source,
            run_id=intent.run_id,
            step=intent.step,
            parent_step=intent.parent_step,
            context_refs=list(intent.context_refs),
            alternatives_considered=list(intent.alternatives_considered),
        )

        if not self._kill_switch_clear(record):
            return False, record
        if not self._rate_limit_ok(record):
            return False, record

        risk = assess(intent)
        record.risk = risk.value

        decision = self.policy.decide(intent, risk)
        if decision.effect == "deny":
            record.event = "denied"
            record.rule_id = decision.rule_id
            record.decision_reason = decision.message or "denied by policy"
            self.audit.append(record)
            return False, record

        forced_confirm = decision.effect == "confirm"

        if (not forced_confirm and self.auto_approve_low
                and risk == RiskLevel.LOW):
            record.decision_reason = decision.message or "auto-approved low risk"
            if decision.rule_id:
                record.rule_id = decision.rule_id
            self.audit.append(record)
            return True, record

        key = consent_key(intent)
        cached = self._consents.get(key)
        if cached in (ConsentLevel.SESSION, ConsentLevel.ALWAYS):
            record.decision_reason = f"consent:{cached.value}"
            self.audit.append(record)
            return True, record

        response = self.confirmer.confirm(ApprovalRequest(  # type: ignore[attr-defined]
            intent=intent, risk=risk,
            rule_id=decision.rule_id, message=decision.message))
        if inspect.isawaitable(response):
            raise TypeError("async confirmer used with sync Gate.check(); "
                            "use gated async functions instead")
        assert isinstance(response, ApprovalResponse)

        if not response.approved:
            record.event = "denied"
            record.decision_reason = response.reason or "rejected"
            record.rule_id = decision.rule_id
            self.audit.append(record)
            return False, record

        if response.consent in (ConsentLevel.SESSION, ConsentLevel.ALWAYS):
            with self._lock:
                self._consents[key] = response.consent

        record.decision_reason = (decision.message
                                  or f"consent:{response.consent.value}")
        self.audit.append(record)
        return True, record

    def __call__(self, fn=None, *, tool: str | None = None,
                 risk: str | RiskLevel | None = None,
                 action_type: ActionType = ActionType.DISPATCH_TOOL):
        """Decorator factory: @gate / @gate(...) around sync or async fns."""
        def decorate(func: Callable) -> Callable:
            name = tool or func.__name__
            level = RiskLevel(risk) if isinstance(risk, str) else risk
            if inspect.iscoroutinefunction(func):
                return self._wrap_async(func, name, level, action_type)
            return self._wrap_sync(func, name, level, action_type)
        if fn is None:
            return decorate
        return decorate(fn)

    def verify(self) -> tuple[bool, str]:
        return self.audit.verify()

    def tail(self, n: int = 50) -> list[AuditRecord]:
        return self.audit.tail(n)

    def clear_session_consents(self) -> None:
        with self._lock:
            self._consents.clear()

    def engage_kill_switch(self, reason: str = "manual") -> None:
        if self.kill_switch_path:
            self.kill_switch_path.write_text(
                f"KILLED at {time.ctime()} reason={reason}", encoding="utf-8")

    def release_kill_switch(self) -> None:
        if self.kill_switch_path and self.kill_switch_path.exists():
            self.kill_switch_path.unlink()

    # ── pipeline internals ─────────────────────────────────────

    @staticmethod
    def _apply_causal(intent: ActionIntent) -> None:
        info = _CAUSAL.get()
        if info is None:
            return
        if info.run_id:
            intent.run_id = info.run_id
        if intent.step is None:
            intent.step = info.step
        if intent.parent_step is None:
            intent.parent_step = info.parent_step
        if not intent.context_refs:
            intent.context_refs = list(info.context_refs)
        if not intent.alternatives_considered:
            intent.alternatives_considered = list(info.alternatives_considered)

    def _kill_switch_clear(self, record: AuditRecord) -> bool:
        if self.kill_switch_path and self.kill_switch_path.exists():
            record.event = "blocked"
            record.decision_reason = "kill switch engaged"
            self.audit.append(record)
            return False
        return True

    def _rate_limit_ok(self, record: AuditRecord) -> bool:
        if not self.rate_limit:
            return True
        max_actions, window = self.rate_limit
        now = time.time()
        with self._lock:
            self._rl_timestamps = [t for t in self._rl_timestamps
                                   if t > now - window]
            if len(self._rl_timestamps) >= max_actions:
                record.event = "rate_limited"
                record.decision_reason = (
                    f"rate limit exceeded ({max_actions}/{window:.0f}s)")
                self.audit.append(record)
                return False
            self._rl_timestamps.append(now)
        return True

    def _record_outcome(self, intent: ActionIntent, base: AuditRecord,
                        event: str, *, state_delta: str = "",
                        error: str = "") -> None:
        outcome = AuditRecord(
            timestamp=time.time(),
            event=event,
            tool=intent.tool,
            action_type=intent.action_type.value,
            risk=base.risk,
            decision_reason=f"after:{base.event}",
            rule_id=base.rule_id,
            source=self.source or intent.source,
            run_id=intent.run_id,
            step=intent.step,
            parent_step=intent.parent_step,
            context_refs=list(intent.context_refs),
            alternatives_considered=list(intent.alternatives_considered),
            state_delta=state_delta,
            error=error,
        )
        self.audit.append(outcome)

    # ── wrappers ───────────────────────────────────────────────

    def _wrap_sync(self, func: Callable, tool: str,
                   level: RiskLevel | None, action_type: ActionType) -> Callable:
        gate = self

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            intent = ActionIntent(
                tool=tool,
                action_type=action_type,
                description=f"{tool}()",
                details=_snapshot(func, args, kwargs),
                risk_level=level,
                source=gate.source,
            )
            approved, base = gate.check(intent)
            if not approved:
                raise Denied(base.decision_reason or "not approved by gate",
                             rule_id=base.rule_id, record=base)
            try:
                result = func(*args, **kwargs)
            except Exception as exc:
                gate._record_outcome(intent, base, "failed",
                                     error=f"{type(exc).__name__}: {exc}"[:300])
                raise
            gate._record_outcome(intent, base, "executed",
                                 state_delta=repr(result)[:200])
            return result

        return wrapper

    def _wrap_async(self, func: Callable, tool: str,
                    level: RiskLevel | None, action_type: ActionType) -> Callable:
        gate = self

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            intent = ActionIntent(
                tool=tool,
                action_type=action_type,
                description=f"{tool}()",
                details=_snapshot(func, args, kwargs),
                risk_level=level,
                source=gate.source,
            )
            approved, base = await self._check_async(intent)
            if not approved:
                raise Denied(base.decision_reason or "not approved by gate",
                             rule_id=base.rule_id, record=base)
            try:
                result = await func(*args, **kwargs)
            except Exception as exc:
                gate._record_outcome(intent, base, "failed",
                                     error=f"{type(exc).__name__}: {exc}"[:300])
                raise
            gate._record_outcome(intent, base, "executed",
                                 state_delta=repr(result)[:200])
            return result

        return wrapper

    async def _check_async(self, intent: ActionIntent) -> tuple[bool, AuditRecord]:
        """Like check(), but awaits async confirmers."""
        self._apply_causal(intent)
        record = AuditRecord(
            timestamp=time.time(),
            event="allowed",
            tool=intent.tool,
            action_type=intent.action_type.value,
            source=self.source or intent.source,
            run_id=intent.run_id,
            step=intent.step,
            parent_step=intent.parent_step,
            context_refs=list(intent.context_refs),
            alternatives_considered=list(intent.alternatives_considered),
        )
        if not self._kill_switch_clear(record):
            return False, record
        if not self._rate_limit_ok(record):
            return False, record

        risk = assess(intent)
        record.risk = risk.value
        decision = self.policy.decide(intent, risk)
        if decision.effect == "deny":
            record.event = "denied"
            record.rule_id = decision.rule_id
            record.decision_reason = decision.message or "denied by policy"
            self.audit.append(record)
            return False, record

        forced_confirm = decision.effect == "confirm"
        if (not forced_confirm and self.auto_approve_low
                and risk == RiskLevel.LOW):
            record.decision_reason = decision.message or "auto-approved low risk"
            self.audit.append(record)
            return True, record

        key = consent_key(intent)
        cached = self._consents.get(key)
        if cached in (ConsentLevel.SESSION, ConsentLevel.ALWAYS):
            record.decision_reason = f"consent:{cached.value}"
            self.audit.append(record)
            return True, record

        request = ApprovalRequest(intent=intent, risk=risk,
                                  rule_id=decision.rule_id,
                                  message=decision.message)
        response = self.confirmer.confirm(request)  # type: ignore[attr-defined]
        if inspect.isawaitable(response):
            response = await response

        if not response.approved:
            record.event = "denied"
            record.decision_reason = response.reason or "rejected"
            record.rule_id = decision.rule_id
            self.audit.append(record)
            return False, record

        if response.consent in (ConsentLevel.SESSION, ConsentLevel.ALWAYS):
            with self._lock:
                self._consents[key] = response.consent

        record.decision_reason = (decision.message
                                  or f"consent:{response.consent.value}")
        self.audit.append(record)
        return True, record
