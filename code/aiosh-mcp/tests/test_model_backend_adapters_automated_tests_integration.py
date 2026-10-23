"""Integration Tests for Automated Test Runner across multi-provider mocks (T-03218)."""

import asyncio
import pytest
from aiosh_mcp.model_backend_adapters_automated_tests import (
    ModelTestCase,
    ModelTestRunner,
)
from aiosh_mcp.model_backend_adapters_data_model import (
    ModelEndpointConfig,
    ModelEndpointRegistry,
    ModelMessage,
    ModelProviderType,
    ModelRequest,
)
from aiosh_mcp.model_backend_adapters_service import ModelBackendService


def test_integration_full_matrix():
    async def _test():
        registry = ModelEndpointRegistry()
        for prov in [ModelProviderType.MOCK, ModelProviderType.OPENAI_COMPATIBLE]:
            bid = f"{prov.value}-backend"
            registry.register(ModelEndpointConfig(
                backend_id=bid,
                provider=prov,
                model_name="test-model",
                timeout_ms=5000,
            ))

        service = ModelBackendService(registry=registry)
        runner = ModelTestRunner(service=service)

        cases = [
            ModelTestCase(
                name=f"test_{prov.value}",
                request=ModelRequest(model_id=f"{prov.value}-backend", messages=[ModelMessage(role="user", content="ping")]),
                expected_status="success",
            )
            for prov in [ModelProviderType.MOCK, ModelProviderType.OPENAI_COMPATIBLE]
        ]

        report = await runner.run_suite(cases)
        assert report.total == 2
        assert report.passed == 2

    asyncio.run(_test())
