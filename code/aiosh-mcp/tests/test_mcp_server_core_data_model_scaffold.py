"""Scaffold test for MCP Server Core data model (T-03065)."""

import pytest
from aiosh_mcp.mcp_server_core_data_model import (
    McpJsonRpcRequest,
    McpJsonRpcResponse,
    McpJsonRpcError,
    McpServerCapabilities,
    ERR_METHOD_NOT_FOUND,
)


def test_mcp_data_model_scaffold_types():
    req = McpJsonRpcRequest(
        jsonrpc="2.0",
        id=101,
        method="tools/list",
    )
    req.validate_scaffold()
    assert req.to_dict()["id"] == 101

    caps = McpServerCapabilities()
    assert caps.tools is True

    err = McpJsonRpcError(
        code=ERR_METHOD_NOT_FOUND,
        message="method not found",
    )
    assert err.code == -32601
