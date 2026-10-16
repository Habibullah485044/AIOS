"""Integration tests for MCP Server Core service (T-03078).

Verifies:
- Production FastMCP integration of `aios_mcp_core_list_tools` and `aios_mcp_core_dispatch`
- Dynamic registration and invocation through FastMCP tool manager
"""

import pytest
import json
from aiosh_mcp.server import mcp
from aiosh_mcp.mcp_server_core_service import (
    get_core_service,
    McpServerCoreService,
)
from aiosh_mcp.mcp_server_core_data_model import (
    McpToolDefinition,
)


def test_integration_mcp_core_service_tools_registered():
    tool_names = [t.name for t in mcp._tool_manager.list_tools()]
    assert "aios_mcp_core_list_tools" in tool_names
    assert "aios_mcp_core_dispatch" in tool_names


@pytest.mark.anyio
async def test_integration_mcp_core_service_dispatch_flow():
    svc = get_core_service()
    tool = McpToolDefinition(
        name="aios.integ.ping",
        description="Integration ping tool",
        input_schema={"type": "object"},
    )
    svc.register_tool(tool)

    # Invoke aios_mcp_core_dispatch through FastMCP
    result = await mcp._tool_manager.call_tool(
        "aios_mcp_core_dispatch",
        {"name": "aios.integ.ping", "arguments": {}},
    )
    assert result is not None
    data = result if isinstance(result, dict) else (json.loads(result[0].text) if hasattr(result[0], "text") else result[0])
    assert data.get("ok") is True
    assert data.get("status") == "success"
