"""MCP handler helpers: gated_tool applies the gate to sync and async handlers."""
import asyncio

from dvarapala import AutoApprove, Gate
from dvarapala.mcp import gated_tool


def test_deploy_service_sync_handler_is_gated_and_audited():
    gate = Gate(confirmer=AutoApprove("test"))

    @gated_tool(gate, risk="low")
    def deploy_service(name: str, image: str) -> str:
        return f"deployed {name} from {image}"

    assert deploy_service("api", "example/api:v1") == (
        "deployed api from example/api:v1"
    )
    record = gate.tail(1)[0]
    assert record.event == "executed"
    assert record.tool == "deploy_service"


def test_deploy_service_async_handler_is_gated_and_audited():
    gate = Gate(confirmer=AutoApprove("test"))

    @gated_tool(gate, risk="low")
    async def deploy_service(name: str, image: str) -> str:
        return f"deployed {name} from {image}"

    assert asyncio.run(deploy_service("api", "example/api:v1")) == (
        "deployed api from example/api:v1"
    )
    record = gate.tail(1)[0]
    assert record.event == "executed"
    assert record.tool == "deploy_service"
