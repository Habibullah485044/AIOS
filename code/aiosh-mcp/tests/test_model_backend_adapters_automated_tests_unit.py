"""Unit Tests for Model Backend Adapters Automated Tests (T-03217)."""

import asyncio
import pytest
from aiosh_mcp.model_backend_adapters_automated_tests import (
    ModelTestCase,
    ModelTestReport,
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


def test_unit_report_aggregation_and_math():
    rep = ModelTestReport(total=4, passed=3, failed=1, duration_ms=150)
    rep_dict = rep.to_dict()
    assert rep_dict["total"] == 4
    assert rep_dict["passed"] == 3
    assert rep_dict["failed"] == 1
    assert rep_dict["pass_rate"] == 0.75
    assert rep_dict["duration_ms"] == 150


def test_unit_secret_redaction_in_test_report():
    async def _test():
        registry = ModelEndpointRegistry()
        service = ModelBackendService(registry=registry)
        runner = ModelTestRunner(service=service)

        case = ModelTestCase(
            name="secret_leak_simulation",
            request=ModelRequest(model_id="bad-sk-secret-key-12345", messages=[ModelMessage(role="user", content="hi")]),
            expected_status="success",
        )
        result = await runner.run_case(case)
        assert result["status"] == "failed"
        assert "sk-" not in (result["error"] or "")

    asyncio.run(_test())
