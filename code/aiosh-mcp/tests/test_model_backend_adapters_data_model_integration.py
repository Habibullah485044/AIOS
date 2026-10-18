"""Integration tests for Model Backend Adapters Data Model FastMCP tools (T-03168)."""

import pytest
from aiosh_mcp.server import mcp


def test_model_adapter_tools_registered():
    tool_names = [t.name for t in mcp._tool_manager.list_tools()]
    assert "aios_model_endpoint_list" in tool_names
    assert "aios_model_endpoint_register" in tool_names


@pytest.mark.anyio
async def test_model_endpoint_list_integration():
    res = await mcp.call_tool("aios_model_endpoint_list", {})
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert '"ok": true' in data.lower()
    assert "mock-default" in data
    assert "openai-primary" in data


@pytest.mark.anyio
async def test_model_endpoint_register_gating():
    # Attempting registration without capability token fails closed
    res = await mcp.call_tool(
        "aios_model_endpoint_register",
        {
            "backend_id": "test-unauth",
            "provider": "mock",
            "model_name": "mock-v1",
            "capability_token": "",
        },
    )
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert '"ok": false' in data.lower()
    assert "capability token required" in data.lower()


@pytest.mark.anyio
async def test_model_endpoint_register_success():
    res = await mcp.call_tool(
        "aios_model_endpoint_register",
        {
            "backend_id": "new-mock-endpoint",
            "provider": "mock",
            "model_name": "mock-eval-2",
            "capability_token": "cap_por_model_register_001",
        },
    )
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert '"ok": true' in data.lower()
    assert "new-mock-endpoint" in data
