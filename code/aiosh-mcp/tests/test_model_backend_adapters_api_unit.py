"""Comprehensive unit tests for Model Backend Adapters MCP/API Surface (T-03197).

Verifies invariants MODAPI-INV1..5:
  - MODAPI-INV1: Wire Tool Schemas & Parameter Validation
  - MODAPI-INV2: Proof-of-Restraint Invariant I-2 Gating
  - MODAPI-INV3: Standardized Result Envelopes & JSON-RPC Error Mapping
  - MODAPI-INV4: Secret & Telemetry Redaction
  - MODAPI-INV5: Fallback & Timeout Bounds
"""

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
)
from aiosh_mcp.model_backend_adapters_service import ModelBackendService


@pytest.fixture
def handler():
    return ModelBackendApiHandler()


# ---------------------------------------------------------------------------
# MODAPI-INV1: Tool Schema & Parameter Validation
# ---------------------------------------------------------------------------

def test_api_parameter_validation_show(handler):
    res_no_param = handler.handle_show(1, {})
    assert res_no_param["error"]["code"] == ERR_INVALID_PARAMS
    assert "Missing 'backend_id'" in res_no_param["error"]["message"]


def test_api_parameter_validation_complete(handler):
    # Missing backend_id
    res_no_bid = handler.handle_complete(2, {"prompt": "hi", "capability_token": "valid-token"})
    assert res_no_bid["error"]["code"] == ERR_INVALID_PARAMS
    assert "Missing 'backend_id'" in res_no_bid["error"]["message"]

    # Missing prompt
    res_no_prompt = handler.handle_complete(3, {"backend_id": "mock-default", "capability_token": "valid-token"})
    assert res_no_prompt["error"]["code"] == ERR_INVALID_PARAMS
    assert "Missing 'prompt'" in res_no_prompt["error"]["message"]


def test_api_parameter_validation_register(handler):
    # Missing parameters
    res = handler.handle_register(4, {"capability_token": "valid-token"})
    assert res["error"]["code"] == ERR_INVALID_PARAMS

    # Invalid provider
    res_prov = handler.handle_register(
        5,
        {
            "backend_id": "b1",
            "provider": "unknown_provider_xyz",
            "model_name": "m1",
            "capability_token": "valid-token",
        },
    )
    assert res_prov["error"]["code"] == ERR_INVALID_PARAMS
    assert "Invalid provider" in res_prov["error"]["message"]


# ---------------------------------------------------------------------------
# MODAPI-INV2: Proof-of-Restraint Token Gating
# ---------------------------------------------------------------------------

def test_por_token_gating_pure_reads(handler):
    """Pure read tools consume 0 capability tokens."""
    res_l = handler.handle_list(10)
    assert res_l["result"]["ok"] is True

    res_s = handler.handle_show(11, {"backend_id": "mock-default"})
    assert res_s["result"]["ok"] is True

    res_h = handler.handle_health(12)
    assert res_h["result"]["ok"] is True


def test_por_token_gating_mutations_rejected(handler):
    """complete and register fail closed with ERR_UNAUTHORIZED if token is missing or whitespace."""
    for token_val in [None, "", "   "]:
        res_c = handler.handle_complete(
            20,
            {"backend_id": "mock-default", "prompt": "hi", "capability_token": token_val},
        )
        assert res_c["error"]["code"] == ERR_UNAUTHORIZED
        assert "capability_token" in res_c["error"]["message"]

        res_r = handler.handle_register(
            21,
            {"backend_id": "b", "provider": "mock", "model_name": "m", "capability_token": token_val},
        )
        assert res_r["error"]["code"] == ERR_UNAUTHORIZED
        assert "capability_token" in res_r["error"]["message"]


# ---------------------------------------------------------------------------
# MODAPI-INV3: Standardized Envelopes & JSON-RPC Error Mapping
# ---------------------------------------------------------------------------

def test_jsonrpc_error_mapping():
    assert ERR_INVALID_PARAMS == -32602
    assert ERR_UNAUTHORIZED == -32003
    assert ERR_NOT_FOUND == -32004
    assert ERR_TIMEOUT == -32005
    assert ERR_INTERNAL == -32603


def test_jsonrpc_request_method_not_found(handler):
    body = {"id": 100, "method": "unrecognized_method"}
    res = handler.handle_request(body)
    assert res["error"]["code"] == -32601


# ---------------------------------------------------------------------------
# MODAPI-INV4: Secret Redaction
# ---------------------------------------------------------------------------

def test_secret_redaction_in_api_errors():
    leak_msg = "Upstream connection failed with Bearer secret-tok-12345 and sk-abcdef0123456789"
    err = make_jsonrpc_error(50, ERR_INTERNAL, leak_msg)
    assert "secret-tok-12345" not in err["error"]["message"]
    assert "sk-abcdef0123456789" not in err["error"]["message"]
    assert "[REDACTED_SECRET]" in err["error"]["message"]


# ---------------------------------------------------------------------------
# MODAPI-INV5: Fallback & Timeout Bounds
# ---------------------------------------------------------------------------

def test_fallback_depth_limit(handler):
    # Exceeding MAX_FALLBACK_DEPTH (5)
    res = handler.handle_complete(
        60,
        {
            "backend_id": "mock-default",
            "prompt": "hi",
            "capability_token": "valid-token",
            "fallbacks": ["f1", "f2", "f3", "f4", "f5", "f6"],
        },
    )
    assert res["error"]["code"] == ERR_INVALID_PARAMS
    assert "Fallback depth" in res["error"]["message"]


def test_timeout_bounds_clamping(handler):
    # Underflow < 1000
    res_under = handler.handle_register(
        70,
        {
            "backend_id": "b-under",
            "provider": "mock",
            "model_name": "m",
            "capability_token": "valid-token",
            "timeout_ms": 500,
        },
    )
    assert res_under["error"]["code"] == ERR_INVALID_PARAMS
    assert "out of bounds" in res_under["error"]["message"]

    # Overflow > 300000
    res_over = handler.handle_register(
        71,
        {
            "backend_id": "b-over",
            "provider": "mock",
            "model_name": "m",
            "capability_token": "valid-token",
            "timeout_ms": 400000,
        },
    )
    assert res_over["error"]["code"] == ERR_INVALID_PARAMS
    assert "out of bounds" in res_over["error"]["message"]
