"""Hardening test suite for Model Backend Adapters Core Service (T-03180)."""

import pytest
from aiosh_mcp.model_backend_adapters_data_model import (
    ModelMessage,
    ModelRequest,
)
from aiosh_mcp.model_backend_adapters_service import (
    MAX_FALLBACK_DEPTH,
    MAX_REQUEST_MESSAGES,
    ModelBackendService,
    ModelServiceError,
    MODSERV_ERR_INVALID_PAYLOAD,
)


@pytest.mark.anyio
async def test_hardening_max_request_messages_ceiling():
    """Verify exceeding MAX_REQUEST_MESSAGES (100) fails closed with invalid payload."""
    svc = ModelBackendService()
    too_many_msgs = [ModelMessage(role="user", content=f"Message {i}") for i in range(MAX_REQUEST_MESSAGES + 1)]
    req = ModelRequest(
        model_id="mock-default",
        messages=too_many_msgs,
    )
    with pytest.raises(ModelServiceError, match=MODSERV_ERR_INVALID_PAYLOAD):
        await svc.complete(req)


@pytest.mark.anyio
async def test_hardening_fallback_chain_depth_limit():
    """Verify exceeding MAX_FALLBACK_DEPTH (5) fails closed."""
    svc = ModelBackendService()
    # 6 distinct backends (primary + 5 fallbacks = 6 > MAX_FALLBACK_DEPTH 5)
    req = ModelRequest(
        model_id="mock-default",
        messages=[ModelMessage(role="user", content="Ping")],
    )
    oversized_fallbacks = [f"fb-{i}" for i in range(5)]
    with pytest.raises(ModelServiceError, match=MODSERV_ERR_INVALID_PAYLOAD):
        await svc.complete(req, fallback_backends=oversized_fallbacks)


@pytest.mark.anyio
async def test_hardening_fallback_chain_deduplication():
    """Verify duplicate and self fallback backends are deduplicated safely."""
    svc = ModelBackendService()
    req = ModelRequest(
        model_id="mock-default",
        messages=[ModelMessage(role="user", content="Ping")],
    )
    # List containing duplicates and primary itself
    duplicates = ["mock-default", "openai-primary", "mock-default", "openai-primary"]
    # Chain length after deduplication will be: ['mock-default', 'openai-primary'] (length 2 <= 5)
    resp = await svc.complete(req, fallback_backends=duplicates)
    assert resp is not None
    assert resp.model == "mock-model-v1"
