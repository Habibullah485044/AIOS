"""Implementation tests for Model Backend Adapters MCP/API surface (T-03196)."""

import pytest

from aiosh_mcp.model_backend_adapters_api import (
    ERR_SUCCESS,
    ERR_INVALID_PARAMS,
    ERR_UNAUTHORIZED,
    ERR_NOT_FOUND,
    ERR_TIMEOUT,
    ERR_INTERNAL,
    ModelBackendApiHandler,
    register_model_backend_tools,
)
from aiosh_mcp.model_backend_adapters_service import ModelBackendService


@pytest.fixture
def handler():
    return ModelBackendApiHandler()


def test_api_list_endpoints(handler):
    res = handler.handle_list("req-1")
    assert res["id"] == "req-1"
    assert res["result"]["ok"] is True
    assert res["result"]["count"] >= 1

    # Filter by provider
    res_filt = handler.handle_list("req-2", {"provider": "mock"})
    assert res_filt["result"]["count"] >= 1
    assert all(e["provider"] == "mock" for e in res_filt["result"]["endpoints"])

    # Active only
    res_act = handler.handle_list("req-3", {"active_only": True})
    assert all(e["is_active"] for e in res_act["result"]["endpoints"])


def test_api_show_endpoint(handler):
    # Valid show
    res = handler.handle_show("req-show-1", {"backend_id": "mock-default"})
    assert res["result"]["ok"] is True
    assert res["result"]["endpoint"]["backend_id"] == "mock-default"

    # Missing backend_id
    res_err = handler.handle_show("req-show-2", {})
    assert "error" in res_err
    assert res_err["error"]["code"] == ERR_INVALID_PARAMS

    # Not found
    res_nf = handler.handle_show("req-show-3", {"backend_id": "nonexistent"})
    assert "error" in res_nf
    assert res_nf["error"]["code"] == ERR_NOT_FOUND


def test_api_health_check(handler):
    # Overall summary
    res = handler.handle_health("req-h-1")
    assert res["result"]["ok"] is True
    assert "active_endpoints" in res["result"]["data"]

    # Target endpoint
    res_t = handler.handle_health("req-h-2", {"backend_id": "mock-default"})
    assert res_t["result"]["ok"] is True
    assert res_t["result"]["data"]["adapter_available"] is True

    # Target unknown
    res_unk = handler.handle_health("req-h-3", {"backend_id": "unknown-backend"})
    assert "error" in res_unk
    assert res_unk["error"]["code"] == ERR_NOT_FOUND


def test_api_complete_execution(handler):
    # Missing token fails with ERR_UNAUTHORIZED (PoR Invariant I-2)
    res_no_tok = handler.handle_complete(
        "req-c-1",
        {"backend_id": "mock-default", "prompt": "test ping"},
    )
    assert res_no_tok["error"]["code"] == ERR_UNAUTHORIZED

    # Authorized complete
    res_ok = handler.handle_complete(
        "req-c-2",
        {
            "backend_id": "mock-default",
            "prompt": "test ping",
            "capability_token": "grant-token-123",
            "temperature": 0.5,
        },
    )
    assert res_ok["result"]["ok"] is True
    assert "Mock execution successful" in res_ok["result"]["response"]["content"]

    # Temperature bounds check
    res_temp = handler.handle_complete(
        "req-c-3",
        {
            "backend_id": "mock-default",
            "prompt": "test ping",
            "capability_token": "grant-token-123",
            "temperature": 2.5,
        },
    )
    assert res_temp["error"]["code"] == ERR_INVALID_PARAMS


def test_api_register_and_verify(handler):
    # Missing token fails with ERR_UNAUTHORIZED (PoR Invariant I-2)
    res_no_tok = handler.handle_register(
        "req-r-1",
        {"backend_id": "dynamic-1", "provider": "mock", "model_name": "m1"},
    )
    assert res_no_tok["error"]["code"] == ERR_UNAUTHORIZED

    # Authorized registration
    res_ok = handler.handle_register(
        "req-r-2",
        {
            "backend_id": "dynamic-1",
            "provider": "mock",
            "model_name": "m1",
            "capability_token": "grant-token-123",
            "timeout_ms": 10000,
        },
    )
    assert res_ok["result"]["ok"] is True
    assert res_ok["result"]["registered"]["backend_id"] == "dynamic-1"

    # Verify endpoint exists in show
    res_show = handler.handle_show("req-r-3", {"backend_id": "dynamic-1"})
    assert res_show["result"]["ok"] is True
    assert res_show["result"]["endpoint"]["model_name"] == "m1"


def test_api_handle_request_dispatch(handler):
    req_ping = {"id": 1, "method": "ping"}
    res_ping = handler.handle_request(req_ping)
    assert res_ping["result"]["status"] == "ok"

    req_tools = {"id": 2, "method": "tools/list"}
    res_tools = handler.handle_request(req_tools)
    assert res_tools["result"]["ok"] is True

    req_unk = {"id": 3, "method": "nonexistent_method"}
    res_unk = handler.handle_request(req_unk)
    assert res_unk["error"]["code"] == -32601


def test_fastmcp_tool_registration(handler):
    class MockFastMCP:
        def __init__(self):
            self.tools = {}

        def tool(self, name: str, description: str):
            def decorator(fn):
                self.tools[name] = fn
                return fn
            return decorator

    app = MockFastMCP()
    register_model_backend_tools(app, service=handler.service)
    assert "model_backend_list" in app.tools
    assert "model_backend_show" in app.tools
    assert "model_backend_health" in app.tools
    assert "model_backend_complete" in app.tools
    assert "model_backend_register" in app.tools

    # Test tool invocation
    out = app.tools["model_backend_list"]()
    assert out["result"]["ok"] is True
