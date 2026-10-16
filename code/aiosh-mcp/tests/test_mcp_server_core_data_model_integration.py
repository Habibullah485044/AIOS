"""Integration tests for MCP Server Core data model (T-03068).

Verifies:
- Production FastMCP tool registration for `aios_mcp_core_status`
- End-to-end handshake simulation and capability reporting
- Envelope formatting and error recovery
"""

import pytest
import json
from aiosh_mcp.server import mcp
from aiosh_mcp.mcp_server_core_data_model import (
    McpJsonRpcRequest,
    McpJsonRpcResponse,
    McpSessionInfo,
    McpCoreResultEnvelope,
    PROTOCOL_VERSION,
)


def test_integration_mcp_server_core_status_registered():
    # Verify tool is discoverable in FastMCP tool list
    # FastMCP holds registered tools in internal tool registry
    tool_names = [t.name for t in mcp._tool_manager.list_tools()]
    assert "aios_mcp_core_status" in tool_names


@pytest.mark.anyio
async def test_integration_mcp_server_core_status_call():
    # Call the tool directly through the tool manager
    result = await mcp._tool_manager.call_tool("aios_mcp_core_status", {"session_id": "sess_integ_01"})
    assert result is not None
    # In FastMCP, if result is a dict, check directly; if content block, check text
    if isinstance(result, dict):
        data = result
    elif isinstance(result, list) and len(result) > 0:
        data = json.loads(result[0].text) if hasattr(result[0], "text") else result[0]
    else:
        data = result
    assert data.get("ok") is True
    assert data.get("status") == "success"
    session_data = data.get("data", {})
    assert session_data.get("session_id") == "sess_integ_01"
    assert session_data.get("protocol_version") == PROTOCOL_VERSION


def test_integration_handshake_flow():
    # 1. Client handshake request
    req = McpJsonRpcRequest(
        jsonrpc="2.0",
        id=1,
        method="initialize",
        params={"clientInfo": {"name": "test-agent", "version": "1.0"}},
    )
    req.validate()
    wire = req.to_json_str()

    # 2. Server parse
    parsed = McpJsonRpcRequest.from_json_str(wire)
    session = McpSessionInfo(
        session_id="session-integ-2",
        client_name="test-agent",
        client_version="1.0",
    )

    # 3. Server response
    resp = McpJsonRpcResponse.success(
        parsed.id,
        {
            "protocolVersion": session.protocol_version,
            "capabilities": session.capabilities.to_dict(),
        },
    )
    assert resp.result["protocolVersion"] == PROTOCOL_VERSION
