"""Helpers for gating MCP (Model Context Protocol) server tool handlers.

MCP tools are the highest-value integration surface: every MCP server
author inherits policy checks, consent prompts, and a hash-chained audit
log with one decorator::

    from dvarapala import Gate
    from dvarapala.mcp import gated_tool

    gate = Gate(policy="policy.json", audit="mcp-audit.jsonl")

    @gated_tool(gate, risk="high")
    async def deploy_service(name: str, image: str) -> str: ...
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .gate import Gate


def gated_tool(gate: Gate, *, tool: str | None = None,
               risk: str | None = None) -> Callable[[Any], Any]:
    """Decorator factory for MCP-style tool handlers (sync or async)."""
    return gate(tool=tool, risk=risk)
