"""MCP stdio proxy: gating logic without spawning real servers."""
import json

from dvarapala import AutoApprove, Gate, ProxySession


def make_session(policy=None, **kw):
    gate = Gate(confirmer=AutoApprove("t"),
                policy=policy or {
                    "rules": [
                        {"id": "no-delete", "match": {"tool": "delete_*"},
                         "effect": "deny", "message": "deletes are forbidden"},
                        {"id": "reads-free", "match": {"tool": "read_*"},
                         "effect": "allow"},
                    ]})
    return ProxySession(gate, **kw)


def test_blocked_call_returns_jsonrpc_error():
    s = make_session()
    req = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                      "params": {"name": "delete_user",
                                 "arguments": {"uid": "1"}}})
    out = s.on_client_line(req)
    assert out is not None
    msg = json.loads(out)
    assert msg["id"] == 7
    assert msg["error"]["code"] == -32001
    assert "forbidden" in msg["error"]["message"]
    assert msg["error"]["data"]["rule_id"] == "no-delete"


def test_allowed_call_is_forwarded_untouched():
    s = make_session()
    req = json.dumps({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                      "params": {"name": "read_file",
                                 "arguments": {"path": "/tmp/x"}}})
    assert s.on_client_line(req) is None


def test_unrelated_methods_pass_through():
    s = make_session()
    ping = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert s.on_client_line(ping) is None
    assert s.on_server_line(json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": {}})) != ""


def test_malformed_json_forwarded_verbatim():
    s = make_session()
    assert s.on_client_line("not json at all\n") is None
    assert s.on_server_line("garbage\n") == "garbage\n"


def test_tools_list_filters_denied_tools():
    s = make_session()
    listing_req = json.dumps({"jsonrpc": "2.0", "id": 21,
                              "method": "tools/list"})
    assert s.on_client_line(listing_req) is None  # forwarded

    response = {"jsonrpc": "2.0", "id": 21,
                "result": {"tools": [
                    {"name": "read_file", "description": "r"},
                    {"name": "delete_user", "description": "d"},
                    {"name": "delete_everything", "description": "D"},
                    {"name": "other", "description": "o"},
                ]}}
    out = json.loads(s.on_server_line(json.dumps(response)))
    names = [t["name"] for t in out["result"]["tools"]]
    assert names == ["read_file", "other"]


def test_hide_denied_disabled_keeps_all_tools():
    s = make_session(hide_denied=False)
    out = s.on_server_line(json.dumps({"jsonrpc": "2.0", "id": 3,
                                       "result": {"tools": [
                                           {"name": "delete_user"}]}}))
    assert "delete_user" in out


def test_denied_call_lands_in_audit_log(tmp_path):
    gate = Gate(confirmer=AutoApprove("t"), audit=str(tmp_path / "a.jsonl"),
                policy={"rules": [{"id": "d", "match": {"tool": "boom"},
                                   "effect": "deny"}]})
    s = ProxySession(gate)
    req = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                      "params": {"name": "boom"}})
    assert s.on_client_line(req) is not None
    ok, msg = gate.verify(strict=True)
    assert ok, msg
    events = [r.event for r in gate.tail(10)]
    assert "denied" in events
