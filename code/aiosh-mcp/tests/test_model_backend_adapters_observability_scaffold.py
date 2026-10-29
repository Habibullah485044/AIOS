"""Scaffold verification tests for Model Backend Adapters Observability (T-03235)."""

import pytest
from aiosh_mcp.model_backend_adapters_observability import (
    HealthStatus,
    ModelBackendMetricsSnapshot,
    ModelBackendObservabilityService,
    sanitize_telemetry_text,
)


def test_scaffold_types_and_exports():
    assert HealthStatus.HEALTHY == "HEALTHY"
    assert HealthStatus.DEGRADED == "DEGRADED"
    assert HealthStatus.CRITICAL == "CRITICAL"

    service = ModelBackendObservabilityService()
    assert service is not None

    sanitized = sanitize_telemetry_text("normal text\x00\u200b")
    assert "\x00" not in sanitized
    assert "\u200b" not in sanitized
    assert "normal text" in sanitized


def test_scaffold_methods_callable():
    service = ModelBackendObservabilityService()
    service.record_completion("mock", 100.0, 10, 20)
    service.record_failure("mock", "TIMEOUT")
    snap = service.get_snapshot()
    assert snap is not None
    assert snap.total_requests == 2
