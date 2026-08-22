"""ASGI middleware: gating, passthrough, body replay."""
import asyncio
import json

from dvarapala import AutoApprove, DenyAll, Gate
from dvarapala.middleware import ASGIGateMiddleware


def make_scope(method="POST", path="/api/tools/refund", query=b""):
    return {"type": "http", "method": method, "path": path,
            "query_string": query, "headers": []}


def make_receive(body=b'{"amount": 5000}'):
    async def recv():
        return {"type": "http.request", "body": body, "more_body": False}
    return recv


class App:
    def __init__(self):
        self.called = False
        self.received_body = None

    async def __call__(self, scope, receive, send):
        self.called = True
        msg = await receive()
        self.received_body = msg.get("body", b"")
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b'{"ok": true}'})


async def list_send(sent, msg):
    sent.append(msg)


def test_denied_request_gets_403_and_app_not_called():
    app = App()
    gate = Gate(confirmer=DenyAll("money movement disabled"),
                policy={"rules": [
                    {"id": "confirm-mutations",
                     "match": {"tool": "POST /api/tools/refund"},
                     "effect": "confirm"}]})
    mw = ASGIGateMiddleware(app, gate)
    sent = []

    async def scenario():
        await mw(make_scope(), make_receive(),
                 lambda msg: list_send(sent, msg))

    asyncio.run(scenario())

    assert not app.called
    assert sent[0]["status"] == 403
    payload = json.loads(sent[1]["body"])
    assert payload["error"] == "denied_by_dvarapala"
    assert "money movement" in payload["detail"]


def test_approved_request_passes_through_with_body():
    app = App()
    gate = Gate(confirmer=AutoApprove("test"))
    mw = ASGIGateMiddleware(app, gate)
    sent = []

    async def scenario():
        await mw(make_scope(), make_receive(b'{"amount": 5000}'),
                 lambda msg: list_send(sent, msg))

    asyncio.run(scenario())

    assert app.called
    assert app.received_body == b'{"amount": 5000}'
    assert sent[0]["status"] == 200


def test_safe_methods_bypass_gate():
    app = App()
    gate = Gate(confirmer=DenyAll("gate must never see GET"))
    mw = ASGIGateMiddleware(app, gate)
    sent = []

    async def scenario():
        await mw(make_scope(method="GET"), make_receive(b""),
                 lambda msg: list_send(sent, msg))

    asyncio.run(scenario())

    assert app.called
    assert sent[0]["status"] == 200
    assert len(gate.tail(10)) == 0   # gate untouched: nothing audited


def test_prefix_filtering():
    app = App()
    gate = Gate(confirmer=DenyAll())
    mw = ASGIGateMiddleware(app, gate, path_prefixes=("/api/tools/",))
    sent = []

    async def scenario():
        await mw(make_scope(path="/health"), make_receive(b""),
                 lambda msg: list_send(sent, msg))

    asyncio.run(scenario())

    assert app.called
    assert len(gate.tail(10)) == 0   # /health outside prefix → not gated
