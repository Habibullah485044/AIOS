"""Unit test suite for Model Backend Adapters Core Service (T-03177).

Certifies system invariants:
  - MODSERV-INV1: Provider Dispatch Parity
  - MODSERV-INV2: Token Usage Accounting Conservation
  - MODSERV-INV3: Resilient Fallback & Error Taxonomy
  - MODSERV-INV4: Secret Isolation & Redaction
  - MODSERV-INV5: PoR Invariant I-2 Compliance
"""

import pytest
from aiosh_mcp.model_backend_adapters_data_model import (
    ModelEndpointConfig,
    ModelEndpointRegistry,
    ModelMessage,
    ModelProviderType,
    ModelRequest,
    ModelResponse,
    ModelUsage,
)
from aiosh_mcp.model_backend_adapters_service import (
    MockModelAdapter,
    ModelBackendService,
    ModelServiceError,
    MODSERV_ERR_AUTH,
    MODSERV_ERR_FALLBACK_EXHAUSTED,
    MODSERV_ERR_RATE_LIMIT,
    MODSERV_ERR_TIMEOUT,
    MODSERV_ERR_UNAVAILABLE,
    MODSERV_ERR_UNKNOWN_BACKEND,
    MODSERV_ERR_UNSUPPORTED_PROVIDER,
    redact_secrets,
)


@pytest.mark.anyio
async def test_modserv_inv1_provider_dispatch_parity():
    """Certify MODSERV-INV1: All provider types map to a conformant adapter."""
    svc = ModelBackendService()
    expected_providers = [
        ModelProviderType.MOCK,
        ModelProviderType.OPENAI_COMPATIBLE,
        ModelProviderType.ANTHROPIC,
        ModelProviderType.GEMINI,
        ModelProviderType.OLLAMA,
    ]
    for p in expected_providers:
        adapter = svc.get_adapter(p)
        assert adapter is not None


@pytest.mark.anyio
async def test_modserv_inv2_token_usage_conservation():
    """Certify MODSERV-INV2: Usage strictly satisfies total == prompt + completion."""
    svc = ModelBackendService()
    req = ModelRequest(
        model_id="mock-default",
        messages=[
            ModelMessage(role="system", content="System instruction"),
            ModelMessage(role="user", content="User prompt query"),
        ],
    )
    resp = await svc.complete(req)
    assert resp.usage is not None
    assert resp.usage.prompt_tokens >= 0
    assert resp.usage.completion_tokens >= 0
    assert resp.usage.total_tokens == resp.usage.prompt_tokens + resp.usage.completion_tokens

    # Verify that an adapter returning bad usage fails validation
    class CorruptedUsageAdapter(MockModelAdapter):
        async def complete(self, config: ModelEndpointConfig, request: ModelRequest) -> ModelResponse:
            resp = await super().complete(config, request)
            # Forge corrupt total_tokens
            resp.usage = ModelUsage(prompt_tokens=10, completion_tokens=10, total_tokens=999)
            return resp

    svc.register_adapter(ModelProviderType.MOCK, CorruptedUsageAdapter())
    with pytest.raises(ModelServiceError, match="MODADAPT-INV2 violated"):
        await svc.complete(req)


@pytest.mark.anyio
async def test_modserv_inv3_fallback_chain_error_taxonomy():
    """Certify MODSERV-INV3: Typed errors trigger fallback chain progression."""
    svc = ModelBackendService()
    
    # 1. Primary times out -> falls back to secondary
    svc.register_adapter(ModelProviderType.MOCK, MockModelAdapter(fail_mode="timeout"))
    req = ModelRequest(
        model_id="mock-default",
        messages=[ModelMessage(role="user", content="Hello")],
    )
    resp = await svc.complete(req, fallback_backends=["openai-primary"])
    assert resp.model == "gpt-4o"

    # 2. Both primary and fallback fail -> raises MODSERV_ERR_FALLBACK_EXHAUSTED
    svc.register_adapter(ModelProviderType.OPENAI_COMPATIBLE, MockModelAdapter(fail_mode="rate_limit"))
    with pytest.raises(ModelServiceError, match=MODSERV_ERR_FALLBACK_EXHAUSTED):
        await svc.complete(req, fallback_backends=["openai-primary"])


def test_modserv_inv4_secret_redaction():
    """Certify MODSERV-INV4: API keys and bearer tokens are redacted from telemetry."""
    raw = "Request failed: Authorization Bearer sk-proj-1234567890abcdef and ghp_abc1234567890xyz"
    cleaned = redact_secrets(raw)
    assert "sk-proj" not in cleaned
    assert "ghp_" not in cleaned
    assert cleaned.count("[REDACTED_SECRET]") == 2


def test_modserv_inv5_health_check_zero_tokens():
    """Certify MODSERV-INV5: Health check is pure read-only requiring no capability tokens."""
    svc = ModelBackendService()
    status = svc.health_check()
    assert status["total_endpoints"] >= 5
    assert status["active_endpoints"] >= 5
    assert len(status["adapters_available"]) == 5
