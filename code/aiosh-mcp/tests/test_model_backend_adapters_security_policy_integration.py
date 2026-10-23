"""Integration Tests for Security Policy with Model Backend Service (T-03228)."""

import asyncio
import pytest
from aiosh_mcp.model_backend_adapters_security_policy import ModelSecurityPolicy
from aiosh_mcp.model_backend_adapters_data_model import (
    ModelEndpointConfig,
    ModelEndpointRegistry,
    ModelMessage,
    ModelProviderType,
    ModelRequest,
)
from aiosh_mcp.model_backend_adapters_service import ModelBackendService


def test_integration_secpol_with_service_invocation():
    async def _test():
        policy = ModelSecurityPolicy(require_tokens=True)
        registry = ModelEndpointRegistry()
        registry.register(ModelEndpointConfig(
            backend_id="sec-mock",
            provider=ModelProviderType.MOCK,
            model_name="mock-v1",
            timeout_ms=5000,
        ))
        service = ModelBackendService(registry=registry)

        verdict = policy.evaluate("complete", token="cap_granted_123")
        assert verdict.allowed is True

        req = ModelRequest(model_id="sec-mock", messages=[ModelMessage(role="user", content="safe request")])
        resp = await service.complete(req)
        assert resp.model == "mock-v1"

    asyncio.run(_test())
