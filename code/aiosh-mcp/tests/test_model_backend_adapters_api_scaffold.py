"""Scaffold tests for Model Backend Adapters MCP/API surface (T-03195)."""

import pytest

from aiosh_mcp.model_backend_adapters_api import (
    ERR_SUCCESS,
    ERR_INVALID_PARAMS,
    ERR_UNAUTHORIZED,
    ERR_NOT_FOUND,
    ERR_TIMEOUT,
    ERR_INTERNAL,
    ModelBackendApiHandler,
    make_jsonrpc_error,
    make_jsonrpc_result,
    PROTOCOL_VERSION,
)
from aiosh_mcp.model_backend_adapters_service import ModelBackendService


def test_api_constants_contract():
    assert ERR_SUCCESS == 0
    assert ERR_INVALID_PARAMS == -32602
    assert ERR_UNAUTHORIZED == -32003
    assert ERR_NOT_FOUND == -32004
    assert ERR_TIMEOUT == -32005
    assert PROTOCOL_VERSION == "2025-06-18"


def test_make_jsonrpc_envelopes():
    res = make_jsonrpc_result(1, {"k": "v"})
    assert res["jsonrpc"] == "2.0"
    assert res["id"] == 1
    assert res["result"] == {"k": "v"}

    err = make_jsonrpc_error(2, ERR_UNAUTHORIZED, "Unauthorized access with Bearer secret-tok")
    assert err["jsonrpc"] == "2.0"
    assert err["id"] == 2
    assert err["error"]["code"] == ERR_UNAUTHORIZED
    assert "[REDACTED_SECRET]" in err["error"]["message"]


def test_api_handler_ping():
    handler = ModelBackendApiHandler()
    res = handler.handle_ping("test-id")
    assert res["id"] == "test-id"
    assert res["result"]["status"] == "ok"
    assert res["result"]["protocolVersion"] == "2025-06-18"


def test_api_por_token_gating_scaffold():
    handler = ModelBackendApiHandler()
    # Pure read list requires no token
    res_list = handler.handle_list("req-1")
    assert "result" in res_list
    assert res_list["result"]["ok"] is True

    # Complete without token rejected with ERR_UNAUTHORIZED
    res_comp = handler.handle_complete("req-2", {"backend_id": "mock-default", "prompt": "hi"})
    assert "error" in res_comp
    assert res_comp["error"]["code"] == ERR_UNAUTHORIZED

    # Register without token rejected with ERR_UNAUTHORIZED
    res_reg = handler.handle_register("req-3", {"backend_id": "b1", "provider": "mock", "model_name": "m"})
    assert "error" in res_reg
    assert res_reg["error"]["code"] == ERR_UNAUTHORIZED
