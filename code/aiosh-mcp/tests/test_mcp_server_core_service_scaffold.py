"""Scaffold test for MCP Server Core service (T-03075)."""

import pytest
from aiosh_mcp.mcp_server_core_service import (
    McpServerCoreService,
    McpSessionStatus,
)
from aiosh_mcp.mcp_server_core_data_model import (
    McpToolDefinition,
    McpToolCall,
)


def test_mcp_core_service_scaffold_types():
    service = McpServerCoreService()
    tool_def = McpToolDefinition(name="aios.test.ping", description="ping test", input_schema={})
    service.register_tool(tool_def)

    session = service.create_session("sess-scaffold-01", "agent", "1.0")
    assert session.status == McpSessionStatus.ACTIVE

    call = McpToolCall(name="aios.test.ping", arguments={})
    result = service.dispatch_tool_call(call)
    assert not result.is_error
    assert "aios.test.ping" in result.content[0].text
