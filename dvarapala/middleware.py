"""ASGI middleware: gate mutating HTTP requests through Dvarapala.

Wrap any ASGI app::

    from dvarapala import Gate
    from dvarapala.middleware import ASGIGateMiddleware

    gate = Gate(policy="policy.json", audit="audit.jsonl", confirmer="deny")
    app = ASGIGateMiddleware(app, gate, path_prefixes=("/api/tools/",))

POST/PUT/PATCH/DELETE requests under the configured prefixes are checked
against policy before reaching the app; denied requests get a 403 JSON
response and an audit record. GET/HEAD/OPTIONS pass through untouched.
"""
from __future__ import annotations

import json
from typing import Any

from .intent import ActionIntent, ActionType

_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


class ASGIGateMiddleware:
    def __init__(self, app: Any, gate: Any,
                 *, path_prefixes: tuple[str, ...] = ("/",),
                 gated_methods: set[str] | None = None,
                 body_preview_bytes: int = 512):
        self.app = app
        self.gate = gate
        self.path_prefixes = tuple(path_prefixes)
        self.gated_methods = set(gated_methods) if gated_methods else set(_MUTATING)
        self.body_preview_bytes = body_preview_bytes

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "").upper()
        path = scope.get("path", "")
        if (method not in self.gated_methods
                or not any(path.startswith(p) for p in self.path_prefixes)):
            await self.app(scope, receive, send)
            return

        messages, body = await _drain_body(receive, self.body_preview_bytes)

        intent = ActionIntent(
            tool=f"{method} {path}",
            action_type=ActionType.DISPATCH_TOOL,
            description=f"{method} {path}",
            details={
                "method": method,
                "path": path,
                "query": scope.get("query_string", b"").decode("latin-1"),
            },
            diff_preview=body.decode("utf-8", errors="replace")[:512],
            risk_level=None,
        )
        approved, record = self.gate.check(intent)
        if not approved:
            payload = json.dumps({
                "error": "denied_by_dvarapala",
                "detail": record.decision_reason,
                "rule_id": record.rule_id,
                "run_id": record.run_id,
            }).encode("utf-8")
            await send({"type": "http.response.start", "status": 403,
                        "headers": [(b"content-type",
                                     b"application/json")]})
            await send({"type": "http.response.body", "body": payload})
            return

        async def replay_receive():
            if messages:
                return messages.pop(0)
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)


async def _drain_body(receive: Any, limit: int) -> tuple[list[dict], bytes]:
    """Collect request-body messages so we can preview then replay them."""
    messages: list[dict] = []
    chunks: list[bytes] = []
    total = 0
    while True:
        msg = await receive()
        messages.append(msg)
        if msg.get("type") == "http.request":
            chunk = msg.get("body", b"")
            if total < limit:
                chunks.append(chunk[:limit - total])
                total += len(chunk)
            if not msg.get("more_body"):
                break
        else:
            break
    return messages, b"".join(chunks)
