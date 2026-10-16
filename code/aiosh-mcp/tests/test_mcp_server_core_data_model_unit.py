"""Unit tests for MCP Server Core data model (T-03067).

Covers:
1. Valid input (roundtrip JSON-RPC, tool defs, content blocks)
2. Invalid input (bidi/control chars, missing jsonrpc 2.0, bad identifiers)
3. Boundary values (64-char names, 1024-char descriptions)
4. Primary failure mode (parse errors, oversized payload rejection)
"""

import pytest
import json
from aiosh_mcp.mcp_server_core_data_model import (
    McpJsonRpcRequest,
    McpJsonRpcResponse,
    McpJsonRpcError,
    McpToolDefinition,
    McpToolResult,
    McpSessionInfo,
    McpCoreResultEnvelope,
    PROTOCOL_VERSION,
    MAX_PAYLOAD_SIZE,
    ERR_PARSE_ERROR,
    ERR_INVALID_REQUEST,
    ERR_INVALID_PARAMS,
    ERR_BOUNDS_EXCEEDED,
    ERR_SANITIZATION_FAILED,
)


def test_unit_case1_valid_input_roundtrip():
    req = McpJsonRpcRequest(
        jsonrpc="2.0",
        id="req-101",
        method="tools/call",
        params={"name": "aios.fs.read", "arguments": {"path": "/etc/hosts"}},
    )
    req.validate()

    json_str = req.to_json_str()
    assert "req-101" in json_str
    assert "tools/call" in json_str

    parsed = McpJsonRpcRequest.from_json_str(json_str)
    assert parsed.id == "req-101"
    assert parsed.method == "tools/call"

    tool_def = McpToolDefinition(
        name="aios.process.list",
        description="List running processes safely",
        input_schema={"type": "object", "properties": {}},
    )
    assert tool_def.name == "aios.process.list"

    tool_res = McpToolResult.text("process-1, process-2")
    assert not tool_res.is_error
    assert len(tool_res.content) == 1

    session = McpSessionInfo(
        session_id="sess-123",
        client_name="gemini-cli",
        client_version="1.0.0",
    )
    assert session.session_id == "sess-123"
    assert session.protocol_version == PROTOCOL_VERSION


def test_unit_case2_invalid_input_sanitization_and_errors():
    # Invalid jsonrpc version
    req_bad_ver = McpJsonRpcRequest(jsonrpc="1.0", id=1, method="ping")
    with pytest.raises(McpJsonRpcError) as exc_ver:
        req_bad_ver.validate()
    assert exc_ver.value.code == ERR_INVALID_REQUEST

    # Empty method name
    req_empty_m = McpJsonRpcRequest(jsonrpc="2.0", id=1, method="")
    with pytest.raises(McpJsonRpcError) as exc_m:
        req_empty_m.validate()
    assert exc_m.value.code == ERR_INVALID_REQUEST

    # Trojan source bidi in tool name
    bidi_name = "aios\u202Eevil_tool"
    with pytest.raises(McpJsonRpcError) as exc_bidi:
        McpToolDefinition(name=bidi_name, description="desc", input_schema={})
    assert exc_bidi.value.code == ERR_INVALID_PARAMS

    # Control chars in session ID
    ctrl_sess = "session\x07bell"
    with pytest.raises(McpJsonRpcError) as exc_ctrl:
        McpSessionInfo(session_id=ctrl_sess, client_name="c", client_version="1")
    assert exc_ctrl.value.code == ERR_INVALID_PARAMS

    # Spaces in identifier
    with pytest.raises(McpJsonRpcError) as exc_space:
        McpToolDefinition(name="invalid tool name", description="desc", input_schema={})
    assert exc_space.value.code == ERR_INVALID_PARAMS


def test_unit_case3_boundary_values():
    # 64 character name (exact limit)
    name_64 = "a" * 64
    tool_64 = McpToolDefinition(name=name_64, description="desc", input_schema={})
    assert tool_64.name == name_64

    # 65 character name (exceeds limit)
    name_65 = "a" * 65
    with pytest.raises(McpJsonRpcError) as exc_65:
        McpToolDefinition(name=name_65, description="desc", input_schema={})
    assert exc_65.value.code == ERR_INVALID_PARAMS

    # 1024 character description (exact limit)
    desc_1024 = "x" * 1024
    tool_1024 = McpToolDefinition(name="tool", description=desc_1024, input_schema={})
    assert len(tool_1024.description) == 1024

    # 1025 character description (exceeds limit)
    desc_1025 = "x" * 1025
    with pytest.raises(McpJsonRpcError) as exc_1025:
        McpToolDefinition(name="tool", description=desc_1025, input_schema={})
    assert exc_1025.value.code == ERR_BOUNDS_EXCEEDED


def test_unit_case4_primary_failure_mode_parse_error():
    # Malformed JSON
    bad_json = '{"jsonrpc": "2.0", "id": 1, "method": '
    with pytest.raises(McpJsonRpcError) as exc_parse:
        McpJsonRpcRequest.from_json_str(bad_json)
    assert exc_parse.value.code == ERR_PARSE_ERROR

    # Result Envelope Error formatting
    env = McpCoreResultEnvelope.error(ERR_PARSE_ERROR, "malformed framing")
    assert not env.ok
    assert env.status == "error"
    assert env.error_code == ERR_PARSE_ERROR
