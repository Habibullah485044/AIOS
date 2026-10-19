"""Integration tests for Model Backend Adapters Core Service FastMCP tools (T-03178)."""

import pytest
from aiosh_mcp.server import mcp


def test_model_service_tools_registered():
    """Verify core service FastMCP tools are registered."""
    tool_names = [t.name for t in mcp._tool_manager.list_tools()]
    assert "aios_model_complete" in tool_names
    assert "aios_model_service_health" in tool_names


@pytest.mark.anyio
async def test_model_service_health_integration():
    """Verify aios_model_service_health runs without tokens (pure read-only)."""
    res = await mcp.call_tool("aios_model_service_health", {})
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert '"ok": true' in data.lower()
    assert "total_endpoints" in data
    assert "mock" in data


@pytest.mark.anyio
async def test_model_complete_gating():
    """Verify aios_model_complete fails closed without capability token (PoR Invariant I-2)."""
    res = await mcp.call_tool(
        "aios_model_complete",
        {
            "model_id": "mock-default",
            "messages": [{"role": "user", "content": "ping"}],
            "capability_token": "",
        },
    )
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert '"ok": false' in data.lower()
    assert "capability token required" in data.lower()


@pytest.mark.anyio
async def test_model_complete_execution():
    """Verify aios_model_complete executes successfully with valid capability token."""
    res = await mcp.call_tool(
        "aios_model_complete",
        {
            "model_id": "mock-default",
            "messages": [{"role": "user", "content": "Hello via FastMCP"}],
            "capability_token": "cap_por_model_complete_001",
        },
    )
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert '"ok": true' in data.lower()
    assert "mock execution successful" in data.lower()
    assert "total_tokens" in data.lower()
