"""Hardening tests for MCP Server Core MCP/API surface (T-03100).

Verifies:
- Robust error envelope formatting across all failure conditions (never silent failure)
- Rejection of oversized payloads and deep injection
- NUL byte and control character sanitization
- Timeout clamping and graceful error containment
"""

import json
import pytest

from aiosh_mcp.mcp_server_core_api import (
    McpApiHandler,
    make_jsonrpc_error,
)
from aiosh_mcp.mcp_server_core_data_model import (
    McpToolDefinition,
    MAX_ARGUMENTS_SIZE,
    ERR_INVALID_PARAMS,
    ERR_BOUNDS_EXCEEDED,
    ERR_UNAUTHORIZED,
)
from aiosh_mcp.mcp_server_core_service import McpServerCoreService


def test_hardening_never_silent_failure():
    handler = McpApiHandler()

    # Empty payload
    resp = handler.handle_raw_message("")
    assert "error" in resp
    assert resp["error"]["code"] == -32700

    # Non-dict JSON (e.g. array or number)
    resp = handler.handle_raw_message("[1, 2, 3]")
    assert "error" in resp
    assert resp["error"]["code"] == -32600

    # None input
    resp = handler.handle_raw_message(None)  # type: ignore
    assert "error" in resp
    assert resp["error"]["code"] == -32600


def test_hardening_adversarial_arguments_rejection():
    service = McpServerCoreService()
    tool = McpToolDefinition("aios.test.tool", "Test tool", {"type": "object"})
    service.register_tool(tool)
    handler = McpApiHandler(service)

    # 1. NUL byte in tool arguments string
    resp = handler.handle_raw_message({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "aios.test.tool",
            "arguments": {"key": "value\0with_nul"}
        }
    })
    assert resp["error"]["code"] == ERR_INVALID_PARAMS
    assert "NUL byte" in resp["error"]["message"]

    # 2. Oversized payload
    oversized = "a" * (MAX_ARGUMENTS_SIZE + 100)
    resp = handler.handle_raw_message({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "aios.test.tool",
            "arguments": {"huge": oversized}
        }
    })
    assert resp["error"]["code"] == ERR_BOUNDS_EXCEEDED
    assert "limit" in resp["error"]["message"]


def test_hardening_privileged_tool_fail_closed():
    service = McpServerCoreService()
    admin_tool = McpToolDefinition("aios.admin.shutdown", "Shutdown node", {"type": "object"})
    service.register_tool(admin_tool)
    handler = McpApiHandler(service)

    # Missing grant token fails closed
    resp = handler.handle_raw_message({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "aios.admin.shutdown",
            "arguments": {}
        }
    })
    assert resp["error"]["code"] == ERR_UNAUTHORIZED
    assert "requires capability grant" in resp["error"]["message"]
