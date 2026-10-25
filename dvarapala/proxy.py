"""MCP stdio proxy: gate ANY MCP server without touching its code.

Sits between an MCP client and a stdio MCP server, intercepting JSON-RPC::

    dvarapala proxy --config policy.json --audit audit.jsonl -- node server.js

Behavior per message:

- ``tools/call``   → gated through the full pipeline (policy, risk,
  consent). Blocked calls get a JSON-RPC error (-32001 deny, -32002
  approval required) and never reach the server. Every decision lands in
  the hash-chained audit log.
- ``tools/list``   → forwarded; the response has policy-denied tools
  stripped so the agent never sees what it cannot call (disable with
  ``hide_denied=False``).
- everything else  → passed through untouched.

The confirmer decides interactive behavior exactly as elsewhere: in a
non-interactive shell the default confirmer denies anything needing
consent; pass ``confirmer="cli"`` to prompt on the terminal.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
from typing import Any

from .gate import Gate
from .intent import ActionIntent, ActionType, RiskLevel

ERR_BLOCKED = -32001
ERR_CONFIRM = -32002


class ProxySession:
    """Line-level MCP filtering logic, isolated from process plumbing
    so it can be tested without spawning real servers."""

    def __init__(self, gate: Gate, *, hide_denied: bool = True):
        self.gate = gate
        self.hide_denied = hide_denied
        self._pending_tools_list: set[Any] = set()
        self._pending_calls: dict[str, tuple[ActionIntent, Any]] = {}
        self._lock = threading.Lock()

    # ── client → server ────────────────────────────────────────

    def on_client_line(self, line: str) -> str | None:
        """Returns an immediate client-bound response, or None to forward."""
        try:
            msg = json.loads(line)
            if not isinstance(msg, dict):
                return None
        except json.JSONDecodeError:
            return None

        method = msg.get("method")
        msg_id = msg.get("id")

        if method == "tools/call" and msg_id is not None:
            return self._gate_call(msg)

        if method == "tools/list" and msg_id is not None and self.hide_denied:
            with self._lock:
                self._pending_tools_list.add(msg_id)

        return None  # forward untouched

    def _gate_call(self, msg: dict) -> str | None:
        params = msg.get("params") or {}
        tool_name = str(params.get("name", ""))
        arguments = params.get("arguments") or {}
        intent = ActionIntent(
            tool=tool_name,
            action_type=ActionType.DISPATCH_TOOL,
            description=f"mcp:{tool_name}",
            details={"arguments": arguments},
            source="mcp-proxy",
        )
        approved, record = self.gate.check(intent)
        if approved:
            with self._lock:
                self._pending_calls[self._id_key(msg.get("id"))] = (intent, record)
            return None
        payload = {
            "jsonrpc": "2.0",
            "id": msg.get("id"),
            "error": {
                "code": ERR_BLOCKED,
                "message": f"dvarapala: {record.decision_reason}",
                "data": {
                    "rule_id": record.rule_id,
                    "risk": record.risk,
                    "run_id": record.run_id,
                },
            },
        }
        return json.dumps(payload) + "\n"

    # ── server → client ────────────────────────────────────────

    def on_server_line(self, line: str) -> str | None:
        """Returns the (possibly filtered) client-bound line, or None."""
        try:
            msg = json.loads(line)
            if not isinstance(msg, dict):
                return line
        except json.JSONDecodeError:
            return line

        self._record_call_outcome(msg)
        if not self.hide_denied:
            return line

        msg_id = msg.get("id")
        with self._lock:
            if msg_id not in self._pending_tools_list:
                return line
            self._pending_tools_list.discard(msg_id)

        result = msg.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            kept = [t for t in result["tools"]
                    if isinstance(t, dict) and not self._denied_tool(t)]
            result["tools"] = kept
        return json.dumps(msg) + "\n"

    @staticmethod
    def _id_key(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    def _record_call_outcome(self, msg: dict) -> None:
        # Server-initiated requests also have IDs; only JSON-RPC responses
        # correlated to an approved tools/call represent a tool outcome.
        if "method" in msg or ("result" not in msg and "error" not in msg):
            return
        key = self._id_key(msg.get("id"))
        with self._lock:
            pending = self._pending_calls.pop(key, None)
        if pending is None:
            return

        intent, record = pending
        result = msg.get("result")
        if "error" in msg:
            event = "failed"
            error = json.dumps(msg["error"], default=str)[:300]
            state_delta = ""
        elif isinstance(result, dict) and result.get("isError") is True:
            event = "failed"
            error = json.dumps(result, default=str)[:300]
            state_delta = ""
        elif "result" in msg:
            event = "executed"
            error = ""
            state_delta = json.dumps(result, default=str)[:200]
        else:
            event = "failed"
            error = "invalid JSON-RPC response: missing result or error"
            state_delta = ""
        self.gate._record_outcome(intent, record, event,
                                  state_delta=state_delta, error=error)

    def fail_pending(self, reason: str) -> None:
        """Audit calls that never received a response before the server exited."""
        with self._lock:
            pending = list(self._pending_calls.values())
            self._pending_calls.clear()
        for intent, record in pending:
            self.gate._record_outcome(intent, record, "failed", error=reason[:300])

    def _denied_tool(self, tool_def: dict) -> bool:
        probe = ActionIntent(
            tool=str(tool_def.get("name", "")),
            action_type=ActionType.DISPATCH_TOOL,
            description=str(tool_def.get("description", "")),
            source="mcp-proxy",
        )
        decision = self.gate.policy.decide(probe, RiskLevel.MEDIUM)
        return decision.effect == "deny"


def serve(server_cmd: list[str], gate: Gate, *,
          hide_denied: bool = True) -> int:
    """Run the proxy until stdin closes. Returns the server's exit code."""
    session = ProxySession(gate, hide_denied=hide_denied)
    proc = subprocess.Popen(
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,
        text=True,
        encoding="utf-8",
        bufsize=1,
    )
    assert proc.stdin is not None and proc.stdout is not None
    write_lock = threading.Lock()

    def _emit(text: str) -> None:
        with write_lock:
            sys.stdout.write(text)
            sys.stdout.flush()

    def _pump_child() -> None:
        for line in proc.stdout:
            out = session.on_server_line(line)
            if out is not None:
                _emit(out if out.endswith("\n") else out + "\n")

    pump = threading.Thread(target=_pump_child, daemon=True)
    pump.start()
    try:
        for raw in sys.stdin:
            reply = session.on_client_line(raw)
            if reply is not None:
                _emit(reply if reply.endswith("\n") else reply + "\n")
                continue
            proc.stdin.write(raw if raw.endswith("\n") else raw + "\n")
            proc.stdin.flush()
    finally:
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            code = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = proc.wait()
        pump.join(timeout=1)
        session.fail_pending(
            f"MCP server exited with status {code} before responding")
    return code
