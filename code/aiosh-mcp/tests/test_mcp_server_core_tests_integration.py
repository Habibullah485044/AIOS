"""Integration test for MCP Server Core Automated Tests Subsystem (T-03118)."""

import pytest
from aiosh_mcp.server import mcp


def test_mcp_tests_integration_tool_registered():
    tool_names = [t.name for t in mcp._tool_manager.list_tools()]
    assert "aios_mcp_test_run" in tool_names


@pytest.mark.anyio
async def test_mcp_tests_integration_call_all():
    res = await mcp.call_tool("aios_mcp_test_run", {})
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert "ok" in data
    assert "mcp_server_core_automated_tests" in data


@pytest.mark.anyio
async def test_mcp_tests_integration_call_category():
    res = await mcp.call_tool("aios_mcp_test_run", {"category": "security"})
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert "ok" in data
    assert "mcp_security_tests" in data


@pytest.mark.anyio
async def test_mcp_tests_integration_invalid_category():
    res = await mcp.call_tool("aios_mcp_test_run", {"category": "invalid_category"})
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert "error" in data or "false" in data.lower()
