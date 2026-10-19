"""Integration tests for Model Backend Adapters MCP/API surface (T-03198).

Tests end-to-end integration across FastMCP server registration,
JSON-RPC 2.0 dispatch, Proof-of-Restraint token enforcement,
and multi-endpoint fallback execution.
"""

import json
import pytest
from typing import Dict, Any

from aiosh_mcp.server import mcp
from aiosh_mcp.model_backend_adapters_api import (
    ModelBackendApiHandler,
    register_model_backend_tools,
    API_METHOD_LIST,
    API_METHOD_SHOW,
    API_METHOD_HEALTH,
    API_METHOD_COMPLETE,
    API_METHOD_REGISTER,
    ERR_UNAUTHORIZED,
    make_jsonrpc_error,
)
from aiosh_mcp.model_backend_adapters_service import ModelBackendService


@pytest.fixture
def service():
    return ModelBackendService()


@pytest.fixture
def api_handler(service):
    return ModelBackendApiHandler(service=service)


def test_fastmcp_server_tool_registration():
    """Verify Model Backend Adapters tools are registered on the FastMCP application."""
    registered_tools = {}
    if hasattr(mcp, "_tool_manager") and hasattr(mcp._tool_manager, "_tools"):
        registered_tools = mcp._tool_manager._tools
    elif hasattr(mcp, "_tools"):
        registered_tools = mcp._tools

    assert "model_backend_list" in registered_tools
    assert "model_backend_show" in registered_tools
    assert "model_backend_health" in registered_tools
    assert "model_backend_complete" in registered_tools
    assert "model_backend_register" in registered_tools


def test_integration_e2e_api_lifecycle(api_handler):
    """End-to-end API lifecycle: list -> register -> show -> health -> complete."""
    # 1. Initial list
    res_list = api_handler.handle_list("req-1", {})
    assert res_list["result"]["ok"] is True
    initial_ids = {e["backend_id"] for e in res_list["result"]["endpoints"]}
    assert "mock-default" in initial_ids

    # 2. Register new backend (requires PoR capability token)
    unauth_reg = api_handler.handle_register("req-2", {
        "backend_id": "api-integ-test",
        "provider": "mock",
        "model_name": "test-model-integ",
    })
    assert unauth_reg["error"]["code"] == ERR_UNAUTHORIZED

    reg_res = api_handler.handle_register("req-3", {
        "backend_id": "api-integ-test",
        "provider": "mock",
        "model_name": "test-model-integ",
        "capability_token": "cap-token-integ-1",
        "timeout_ms": 20000,
    })
    assert reg_res["result"]["ok"] is True
    assert reg_res["result"]["registered"]["backend_id"] == "api-integ-test"

    # 3. Show details
    res_show = api_handler.handle_show("req-4", {"backend_id": "api-integ-test"})
    assert res_show["result"]["ok"] is True
    assert res_show["result"]["endpoint"]["model_name"] == "test-model-integ"
    assert res_show["result"]["endpoint"]["timeout_ms"] == 20000

    # 4. Check health
    res_health = api_handler.handle_health("req-5", {"backend_id": "api-integ-test"})
    assert res_health["result"]["ok"] is True
    assert res_health["result"]["data"]["active"] is True
    assert res_health["result"]["data"]["adapter_available"] is True

    # 5. Execute completion (requires PoR capability token)
    unauth_comp = api_handler.handle_complete("req-6", {
        "backend_id": "api-integ-test",
        "prompt": "Hello integration test",
    })
    assert unauth_comp["error"]["code"] == ERR_UNAUTHORIZED

    res_comp = api_handler.handle_complete("req-7", {
        "backend_id": "api-integ-test",
        "prompt": "Hello integration test",
        "capability_token": "cap-token-integ-2",
        "temperature": 0.5,
    })
    assert res_comp["result"]["ok"] is True
    assert "Mock execution successful" in res_comp["result"]["response"]["content"]


def test_integration_fallback_dispatch(api_handler):
    """Test fallback chain execution through the API handler."""
    comp_req = {
        "jsonrpc": "2.0",
        "id": "req-fallback",
        "method": API_METHOD_COMPLETE,
        "params": {
            "backend_id": "missing-primary",
            "prompt": "Testing fallback dispatch",
            "capability_token": "valid-token-123",
            "fallbacks": ["missing-secondary", "mock-default"],
        },
    }
    resp = api_handler.handle_request(comp_req)
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == "req-fallback"
    assert "result" in resp
    assert resp["result"]["ok"] is True
    assert resp["result"]["response"]["model"] == "mock-model-v1"


def test_integration_jsonrpc_parity_and_redaction(api_handler):
    """Test full JSON-RPC 2.0 envelopes and secret redaction."""
    err = make_jsonrpc_error(
        "req-redact",
        -32602,
        "Invalid token sk-live-secret-test-key-123 and Bearer token-abc-xyz-secret",
    )
    resp_str = json.dumps(err)
    assert "sk-live-secret-test-key-123" not in resp_str
    assert "token-abc-xyz-secret" not in resp_str
    assert "[REDACTED_SECRET]" in resp_str
