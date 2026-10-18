"""Unit tests for MCP Server Core MCP/API surface (T-03097).

Standard 4-case testing battery:
1. Valid input (ping, initialize, tools/list, safe tools/call)
2. Invalid input (malformed JSON, wrong jsonrpc version, missing method, NUL bytes)
3. Boundary values (MAX_ARGUMENTS_SIZE 1 MiB boundary, empty parameters)
4. Primary failure modes (tool not found, unauthorized call to aios.admin.*)
"""

import json
import pytest

from aiosh_mcp.mcp_server_core_api import (
    McpApiHandler,
    PROTOCOL_VERSION,
    SERVER_NAME,
)
from aiosh_mcp.mcp_server_core_data_model import (
    McpToolDefinition,
    MAX_ARGUMENTS_SIZE,
    ERR_INVALID_REQUEST,
    ERR_METHOD_NOT_FOUND,
    ERR_INVALID_PARAMS,
    ERR_BOUNDS_EXCEEDED,
    ERR_UNAUTHORIZED,
)
from aiosh_mcp.mcp_server_core_service import McpServerCoreService


def test_unit_case1_valid_api_requests():
    service = McpServerCoreService()
    tool = McpToolDefinition("aios.fs.read", "Read file", {"type": "object"})
    service.register_tool(tool)
    handler = McpApiHandler(service)

    # 1. Ping
    resp = handler.handle_raw_message({"jsonrpc": "2.0", "id": 10, "method": "ping"})
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 10
    assert resp["result"]["status"] == "ok"

    # 2. Initialize
    resp = handler.handle_raw_message({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "clientInfo": {"name": "test-agent", "version": "1.2.3"}
        }
    })
    assert resp["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert resp["result"]["serverInfo"]["name"] == SERVER_NAME

    # 3. Tools/List
    resp = handler.handle_raw_message({"jsonrpc": "2.0", "id": 12, "method": "tools/list"})
    assert len(resp["result"]["tools"]) == 1
    assert resp["result"]["tools"][0]["name"] == "aios.fs.read"

    # 4. Tools/Call (safe)
    resp = handler.handle_raw_message({
        "jsonrpc": "2.0",
        "id": 13,
        "method": "tools/call",
        "params": {
            "name": "aios.fs.read",
            "arguments": {"path": "/etc/hosts"}
        }
    })
    assert resp["result"]["isError"] is False
    assert len(resp["result"]["content"]) == 1


def test_unit_case2_invalid_api_inputs():
    handler = McpApiHandler()

    # Malformed JSON string
    resp = handler.handle_raw_message("not valid json{")
    assert resp["error"]["code"] == -32700

    # Wrong jsonrpc version
    resp = handler.handle_raw_message({"jsonrpc": "1.0", "id": 1, "method": "ping"})
    assert resp["error"]["code"] == ERR_INVALID_REQUEST

    # Missing method
    resp = handler.handle_raw_message({"jsonrpc": "2.0", "id": 2})
    assert resp["error"]["code"] == ERR_INVALID_REQUEST

    # Unknown method
    resp = handler.handle_raw_message({"jsonrpc": "2.0", "id": 3, "method": "unknown/method"})
    assert resp["error"]["code"] == ERR_METHOD_NOT_FOUND

    # NUL byte in tool name
    resp = handler.handle_raw_message({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "aios.bad\0tool"}
    })
    assert resp["error"]["code"] == ERR_INVALID_PARAMS


def test_unit_case3_boundary_values():
    service = McpServerCoreService()
    tool = McpToolDefinition("aios.echo", "Echo input", {"type": "object"})
    service.register_tool(tool)
    handler = McpApiHandler(service)

    # Empty arguments dict is valid
    resp = handler.handle_raw_message({
        "jsonrpc": "2.0",
        "id": 20,
        "method": "tools/call",
        "params": {"name": "aios.echo", "arguments": {}}
    })
    assert resp["result"]["isError"] is False

    # Oversized arguments payload > 1 MiB
    huge_str = "x" * (MAX_ARGUMENTS_SIZE + 10)
    resp = handler.handle_raw_message({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "tools/call",
        "params": {"name": "aios.echo", "arguments": {"data": huge_str}}
    })
    assert resp["error"]["code"] == ERR_BOUNDS_EXCEEDED


def test_unit_case4_primary_failure_modes():
    service = McpServerCoreService()
    # Register an admin tool
    admin_tool = McpToolDefinition("aios.admin.restart", "Restart daemon", {"type": "object"})
    service.register_tool(admin_tool)
    handler = McpApiHandler(service)

    # 1. Tool not found
    resp = handler.handle_raw_message({
        "jsonrpc": "2.0",
        "id": 30,
        "method": "tools/call",
        "params": {"name": "aios.nonexistent"}
    })
    assert resp["error"] is not None

    # 2. Privileged tool without capability grant fails with ERR_UNAUTHORIZED (-32002)
    resp = handler.handle_raw_message({
        "jsonrpc": "2.0",
        "id": 31,
        "method": "tools/call",
        "params": {"name": "aios.admin.restart", "arguments": {}}
    })
    assert resp["error"]["code"] == ERR_UNAUTHORIZED

    # 3. Privileged tool with capability grant succeeds
    resp = handler.handle_raw_message({
        "jsonrpc": "2.0",
        "id": 32,
        "method": "tools/call",
        "params": {"name": "aios.admin.restart", "arguments": {}, "grant": "grant_token_123"}
    })
    assert resp["result"]["isError"] is False
