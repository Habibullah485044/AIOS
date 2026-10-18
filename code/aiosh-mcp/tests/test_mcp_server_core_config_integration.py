"""Integration test for MCP Server Core Configuration Subsystem (T-03108)."""

import pytest
from aiosh_mcp.server import mcp
from aiosh_mcp.mcp_server_core_config import get_core_config, McpServerCoreConfig


def test_mcp_config_integration_tools_registered():
    tool_names = [t.name for t in mcp._tool_manager.list_tools()]
    assert "aios_mcp_config_get" in tool_names
    assert "aios_mcp_config_validate" in tool_names


@pytest.mark.anyio
async def test_mcp_config_integration_get():
    res = await mcp.call_tool("aios_mcp_config_get", {})
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert "ok" in data
    assert "store_path" in data


@pytest.mark.anyio
async def test_mcp_config_integration_validate():
    valid_payload = {
        "candidate_config": {
            "store_path": ".aios/custom.json",
            "max_active_sessions": 32,
        }
    }
    res = await mcp.call_tool("aios_mcp_config_validate", valid_payload)
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert "valid" in data
    assert "true" in data.lower()

    invalid_payload = {
        "candidate_config": {
            "store_path": "../traversal/path",
        }
    }
    res_inv = await mcp.call_tool("aios_mcp_config_validate", invalid_payload)
    data_inv = res_inv[0].text if hasattr(res_inv[0], "text") else str(res_inv[0])
    assert "error" in data_inv or "false" in data_inv.lower()
