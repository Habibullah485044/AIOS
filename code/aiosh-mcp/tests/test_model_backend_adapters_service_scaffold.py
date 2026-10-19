"""Scaffold tests for Model Backend Adapters Core Service (T-03175)."""

import pytest
from aiosh_mcp.model_backend_adapters_data_model import (
    ModelEndpointConfig,
    ModelEndpointRegistry,
    ModelMessage,
    ModelProviderType,
    ModelRequest,
)
from aiosh_mcp.model_backend_adapters_service import (
    BaseModelAdapter,
    MockModelAdapter,
    ModelBackendService,
    ModelServiceError,
    MODSERV_ERR_UNKNOWN_BACKEND,
    MODSERV_ERR_UNSUPPORTED_PROVIDER,
    MODSERV_ERR_FALLBACK_EXHAUSTED,
)


def test_scaffold_adapter_registration():
    """Verify registration and retrieval of adapters."""
    svc = ModelBackendService()
    # Mock adapter is pre-registered
    adapter = svc.get_adapter(ModelProviderType.MOCK)
    assert isinstance(adapter, MockModelAdapter)

    # Missing adapter raises
    del svc._adapters[ModelProviderType.ANTHROPIC]
    with pytest.raises(ModelServiceError, match=MODSERV_ERR_UNSUPPORTED_PROVIDER):
        svc.get_adapter(ModelProviderType.ANTHROPIC)


@pytest.mark.anyio
async def test_scaffold_mock_completion():
    """Verify basic completion through MockModelAdapter."""
    svc = ModelBackendService()
    req = ModelRequest(
        model_id="mock-default",
        messages=[ModelMessage(role="user", content="Hello AIOS")],
        temperature=0.5,
    )
    resp = await svc.complete(req)
    assert resp.model == "mock-model-v1"
    assert "Mock execution" in resp.content
    assert resp.usage.total_tokens == resp.usage.prompt_tokens + resp.usage.completion_tokens


@pytest.mark.anyio
async def test_scaffold_unknown_backend_fallback_exhausted():
    """Verify unknown backend triggers fallback exhaustion."""
    svc = ModelBackendService()
    req = ModelRequest(
        model_id="non-existent-backend",
        messages=[ModelMessage(role="user", content="ping")],
    )
    with pytest.raises(ModelServiceError, match=MODSERV_ERR_FALLBACK_EXHAUSTED):
        await svc.complete(req)


def test_scaffold_health_check():
    """Verify read-only health check format."""
    svc = ModelBackendService()
    health = svc.health_check()
    assert "total_endpoints" in health
    assert "active_endpoints" in health
    assert "adapters_available" in health
    assert "mock" in health["adapters_available"]
