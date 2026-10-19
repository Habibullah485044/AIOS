"""Implementation tests for Model Backend Adapters Core Service (T-03176)."""

import pytest
from aiosh_mcp.model_backend_adapters_data_model import (
    ModelEndpointConfig,
    ModelEndpointRegistry,
    ModelMessage,
    ModelProviderType,
    ModelRequest,
)
from aiosh_mcp.model_backend_adapters_service import (
    MockModelAdapter,
    ModelBackendService,
    ModelServiceError,
    MODSERV_ERR_FALLBACK_EXHAUSTED,
    MODSERV_ERR_UNKNOWN_BACKEND,
    redact_secrets,
)


@pytest.mark.anyio
async def test_impl_all_provider_adapters():
    """Verify dispatch works across all 5 provider adapters (MODSERV-INV1)."""
    svc = ModelBackendService()
    providers_and_backends = [
        (ModelProviderType.MOCK, "mock-default"),
        (ModelProviderType.OPENAI_COMPATIBLE, "openai-primary"),
        (ModelProviderType.ANTHROPIC, "anthropic-primary"),
        (ModelProviderType.GEMINI, "gemini-primary"),
        (ModelProviderType.OLLAMA, "ollama-local"),
    ]

    for p_type, b_id in providers_and_backends:
        req = ModelRequest(
            model_id=b_id,
            messages=[ModelMessage(role="user", content=f"Test prompt for {p_type.value}")],
            temperature=0.7,
        )
        resp = await svc.complete(req)
        assert resp is not None
        assert resp.usage is not None
        # Enforce MODSERV-INV2
        assert resp.usage.total_tokens == resp.usage.prompt_tokens + resp.usage.completion_tokens
        assert resp.latency_ms > 0.0


@pytest.mark.anyio
async def test_impl_fallback_chain_progression():
    """Verify fallback executes when primary backend encounters failure (MODSERV-INV3)."""
    svc = ModelBackendService()
    # Configure mock adapter with timeout
    failing_adapter = MockModelAdapter(fail_mode="timeout")
    svc.register_adapter(ModelProviderType.MOCK, failing_adapter)

    # Request specifies primary failing backend, with fallback to openai-primary
    req = ModelRequest(
        model_id="mock-default",
        messages=[ModelMessage(role="user", content="Fallback test")],
    )
    resp = await svc.complete(req, fallback_backends=["openai-primary"])
    assert resp.model == "gpt-4o"
    assert "OpenAI" in resp.content


@pytest.mark.anyio
async def test_impl_secret_redaction():
    """Verify secrets are redacted from error messages (MODSERV-INV4)."""
    leak_text = "Failed connecting with Bearer sk-ant-secretkey1234567890 and ghp_githubtoken12345"
    redacted = redact_secrets(leak_text)
    assert "sk-ant" not in redacted
    assert "ghp_" not in redacted
    assert "[REDACTED_SECRET]" in redacted


def test_impl_health_check_filtering():
    """Verify health check filters correctly by backend_id."""
    svc = ModelBackendService()
    health_all = svc.health_check()
    assert health_all["total_endpoints"] >= 5

    health_one = svc.health_check("mock-default")
    assert health_one["total_endpoints"] == 1
    assert health_one["endpoints"][0]["backend_id"] == "mock-default"
