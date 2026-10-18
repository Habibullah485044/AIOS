"""Integration test for MCP Server Core MCP/API surface (T-03098)."""

import pytest
from aiosh_mcp.server import mcp
from aiosh_mcp.mcp_server_core_api import get_api_handler, PROTOCOL_VERSION


def test_mcp_api_integration_tools_registered():
    tool_names = [t.name for t in mcp._tool_manager.list_tools()]
    assert "aios_mcp_api_ping" in tool_names
    assert "aios_mcp_api_jsonrpc" in tool_names


@pytest.mark.anyio
async def test_mcp_api_integration_call_jsonrpc_tool():
    ping_req = '{"jsonrpc": "2.0", "id": 100, "method": "ping"}'
    res = await mcp.call_tool("aios_mcp_api_jsonrpc", {"request": ping_req})
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert "2.0" in data
    assert "ok" in data
