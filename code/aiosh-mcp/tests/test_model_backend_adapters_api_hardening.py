"""Hardening tests for Model Backend Adapters MCP/API surface (T-03200).

Validates strict input sanitization, anti-traversal defenses,
payload size clamping, fallback depth enforcement, and fail-closed error boundaries.
"""

import pytest

from aiosh_mcp.model_backend_adapters_api import (
    ModelBackendApiHandler,
    ERR_INVALID_PARAMS,
    ERR_UNAUTHORIZED,
    validate_backend_id,
)
from aiosh_mcp.model_backend_adapters_service import ModelBackendService


@pytest.fixture
def api_handler():
    return ModelBackendApiHandler()


def test_hardening_validate_backend_id():
    """Test helper for identifier validation."""
    assert validate_backend_id("valid-id_123.test") is None
    assert "cannot be empty" in validate_backend_id("")
    assert "exceeds 64 characters" in validate_backend_id("a" * 65)
    assert "prohibited path traversal" in validate_backend_id("../etc/passwd")
    assert "prohibited path traversal" in validate_backend_id("dir/backend")
    assert "prohibited path traversal" in validate_backend_id("dir\\backend")
    assert "prohibited path traversal" in validate_backend_id("backend\0bad")
    assert "prohibited control characters" in validate_backend_id("bad\x01id")


def test_hardening_show_traversal_rejection(api_handler):
    """Path traversal attempt in show rejects with ERR_INVALID_PARAMS."""
    res = api_handler.handle_show("req-trav-1", {"backend_id": "../../secret"})
    assert res["error"]["code"] == ERR_INVALID_PARAMS
    assert "prohibited path traversal" in res["error"]["message"]


def test_hardening_health_traversal_rejection(api_handler):
    """Path traversal attempt in health rejects with ERR_INVALID_PARAMS."""
    res = api_handler.handle_health("req-trav-2", {"backend_id": "dir/escape"})
    assert res["error"]["code"] == ERR_INVALID_PARAMS
    assert "prohibited path traversal" in res["error"]["message"]


def test_hardening_complete_oversized_prompt(api_handler):
    """Oversized prompt (> 1 MiB) rejected with ERR_INVALID_PARAMS."""
    oversized = "a" * (1024 * 1024 + 10)
    res = api_handler.handle_complete("req-size-1", {
        "backend_id": "mock-default",
        "prompt": oversized,
        "capability_token": "valid-grant",
    })
    assert res["error"]["code"] == ERR_INVALID_PARAMS
    assert "exceeds 1 MiB limit" in res["error"]["message"]


def test_hardening_complete_nul_byte_prompt(api_handler):
    """NUL byte injection in prompt rejected with ERR_INVALID_PARAMS."""
    res = api_handler.handle_complete("req-nul-1", {
        "backend_id": "mock-default",
        "prompt": "hello\0world",
        "capability_token": "valid-grant",
    })
    assert res["error"]["code"] == ERR_INVALID_PARAMS
    assert "prohibited NUL byte" in res["error"]["message"]


def test_hardening_fallback_depth_and_traversal(api_handler):
    """Fallback chain depth > 5 or invalid fallback identifier rejected."""
    # Depth > 5
    res_depth = api_handler.handle_complete("req-fb-1", {
        "backend_id": "mock-default",
        "prompt": "hi",
        "capability_token": "valid-grant",
        "fallbacks": ["fb1", "fb2", "fb3", "fb4", "fb5", "fb6"],
    })
    assert res_depth["error"]["code"] == ERR_INVALID_PARAMS
    assert "Fallback depth (6) exceeds maximum" in res_depth["error"]["message"]

    # Traversal in fallback
    res_trav = api_handler.handle_complete("req-fb-2", {
        "backend_id": "mock-default",
        "prompt": "hi",
        "capability_token": "valid-grant",
        "fallbacks": ["../injected"],
    })
    assert res_trav["error"]["code"] == ERR_INVALID_PARAMS
    assert "Fallback backend invalid" in res_trav["error"]["message"]


def test_hardening_register_bounds(api_handler):
    """Register parameter bounding: length, traversal, timeout."""
    # Length > 64
    res_len = api_handler.handle_register("req-reg-1", {
        "backend_id": "b" * 65,
        "provider": "mock",
        "model_name": "m1",
        "capability_token": "valid-grant",
    })
    assert res_len["error"]["code"] == ERR_INVALID_PARAMS
    assert "exceeds 64 characters" in res_len["error"]["message"]

    # Traversal
    res_trav = api_handler.handle_register("req-reg-2", {
        "backend_id": "bad/id",
        "provider": "mock",
        "model_name": "m1",
        "capability_token": "valid-grant",
    })
    assert res_trav["error"]["code"] == ERR_INVALID_PARAMS
    assert "prohibited path traversal" in res_trav["error"]["message"]

    # Timeout out of bounds
    res_to = api_handler.handle_register("req-reg-3", {
        "backend_id": "good-id",
        "provider": "mock",
        "model_name": "m1",
        "capability_token": "valid-grant",
        "timeout_ms": 500,
    })
    assert res_to["error"]["code"] == ERR_INVALID_PARAMS
    assert "out of bounds [1000, 300000]" in res_to["error"]["message"]
