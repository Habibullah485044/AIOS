"""Implementation tests for Model Backend Adapters Automated Tests (T-03216)."""

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


def test_autotest_runner_happy_and_fault_paths():
    async def _test():
        registry = ModelEndpointRegistry()
        ep = ModelEndpointConfig(
            backend_id="test-mock",
            provider=ModelProviderType.MOCK,
            model_name="mock-v1",
            timeout_ms=5000,
        )
        registry.register(ep)
        service = ModelBackendService(registry=registry)
        runner = ModelTestRunner(service=service)

        cases = [
            ModelTestCase(
                name="valid_completion",
                request=ModelRequest(model_id="test-mock", messages=[ModelMessage(role="user", content="hello")]),
                expected_status="success",
            ),
            ModelTestCase(
                name="unknown_backend_failure",
                request=ModelRequest(model_id="non-existent", messages=[ModelMessage(role="user", content="hello")]),
                expected_status="error",
            ),
        ]

        report = await runner.run_suite(cases)
        assert report.total == 2
        assert report.passed == 2
        assert report.failed == 0
        rep_dict = report.to_dict()
        assert rep_dict["pass_rate"] == 1.0

    asyncio.run(_test())
