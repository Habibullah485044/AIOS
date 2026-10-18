"""Integration tests for MCP Server Core Observability Subsystem (T-03138)."""

import pytest
from aiosh_mcp.server import mcp


def test_mcp_observability_tool_registered():
    tool_names = [t.name for t in mcp._tool_manager.list_tools()]
    assert "aios_mcp_observability_snapshot" in tool_names


@pytest.mark.anyio
async def test_mcp_observability_snapshot_invocation():
    res = await mcp.call_tool("aios_mcp_observability_snapshot", {})
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert '"ok": true' in data.lower()
    assert "uptime_seconds" in data
    assert "health_status" in data
    assert "total_tools_registered" in data
