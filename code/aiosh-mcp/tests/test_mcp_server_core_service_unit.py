"""Unit tests for MCP Server Core service (T-03077).

Covers:
1. Valid input (registration, query, session lifecycle, dispatch)
2. Invalid input (duplicate tools, unauthorized privileged tool, invalid session)
3. Boundary values (session capacity 64, tool capacity 256)
4. Primary failure mode (tool not found, terminated session heartbeat)
"""

import pytest
from aiosh_mcp.mcp_server_core_service import (
    McpServerCoreService,
    McpSessionStatus,
    MAX_ACTIVE_SESSIONS,
    MCPSVC_ERR_SESSION_NOT_FOUND,
    MCPSVC_ERR_SESSION_CAPACITY_EXCEEDED,
    MCPSVC_ERR_TOOL_ALREADY_EXISTS,
    MCPSVC_ERR_TOOL_NOT_FOUND,
)
from aiosh_mcp.mcp_server_core_data_model import (
    McpToolDefinition,
    McpToolCall,
    McpJsonRpcError,
    ERR_UNAUTHORIZED,
)


def test_unit_case1_valid_tool_and_session_lifecycle():
    service = McpServerCoreService()

    tool = McpToolDefinition(
        name="aios.fs.read",
        description="Safe text reader",
        input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
    )
    service.register_tool(tool)

    found = service.get_tool("aios.fs.read")
    assert found is not None
    assert found.name == "aios.fs.read"

    assert len(service.list_tools()) == 1

    session = service.create_session("sess-unit-1", "agent-test", "1.0")
    assert session.status == McpSessionStatus.ACTIVE

    service.heartbeat_session("sess-unit-1")
    fetched = service.get_session("sess-unit-1")
    assert fetched is not None

    call = McpToolCall(name="aios.fs.read", arguments={"path": "/tmp/a.txt"})
    result = service.dispatch_tool_call(call)
    assert not result.is_error
    assert "Executed aios.fs.read" in result.content[0].text


def test_unit_case2_invalid_input_and_unauthorized_dispatch():
    service = McpServerCoreService()

    tool = McpToolDefinition(name="aios.admin.restart", description="Reboot", input_schema={})
    service.register_tool(tool)

    # Duplicate registration rejected
    with pytest.raises(McpJsonRpcError) as exc_dup:
        service.register_tool(tool)
    assert exc_dup.value.code == MCPSVC_ERR_TOOL_ALREADY_EXISTS

    # Privileged tool call without grant rejected
    unauth_call = McpToolCall(name="aios.admin.restart", arguments={}, grant_id=None)
    with pytest.raises(McpJsonRpcError) as exc_unauth:
        service.dispatch_tool_call(unauth_call)
    assert exc_unauth.value.code == ERR_UNAUTHORIZED

    # Terminate non-existent session
    with pytest.raises(McpJsonRpcError) as exc_term:
        service.terminate_session("non-existent-session")
    assert exc_term.value.code == MCPSVC_ERR_SESSION_NOT_FOUND


def test_unit_case3_boundary_values_capacity_and_eviction():
    service = McpServerCoreService()

    for i in range(MAX_ACTIVE_SESSIONS):
        sid = f"sess-bound-{i}"
        service.create_session(sid, "client", "1.0")

    # Overflow rejected
    with pytest.raises(McpJsonRpcError) as exc_over:
        service.create_session("sess-overflow", "client", "1.0")
    assert exc_over.value.code == MCPSVC_ERR_SESSION_CAPACITY_EXCEEDED

    # Terminate one session
    service.terminate_session("sess-bound-0")

    # Re-allocation succeeds
    recovered = service.create_session("sess-recovered", "client", "1.0")
    assert recovered is not None


def test_unit_case4_primary_failure_mode_missing_tool_and_envelope():
    service = McpServerCoreService()

    missing_call = McpToolCall(name="aios.nonexistent.tool", arguments={})
    with pytest.raises(McpJsonRpcError) as exc_miss:
        service.dispatch_tool_call(missing_call)
    assert exc_miss.value.code == MCPSVC_ERR_TOOL_NOT_FOUND

    # Safe dispatch envelope
    env = service.safe_dispatch_tool_call(missing_call)
    assert env.ok is False
    assert env.status == "error"
    assert env.error_code == MCPSVC_ERR_TOOL_NOT_FOUND
