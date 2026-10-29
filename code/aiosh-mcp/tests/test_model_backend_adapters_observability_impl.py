"""Implementation verification tests for Model Backend Adapters Observability (T-03236)."""

import pytest
from aiosh_mcp.model_backend_adapters_observability import (
    HealthStatus,
    ModelBackendObservabilityService,
)


def test_impl_record_completion_and_snapshot():
    service = ModelBackendObservabilityService()
    service.record_completion(provider="mock", duration_ms=120.0, prompt_tokens=50, completion_tokens=30)
    service.record_completion(provider="mock", duration_ms=80.0, prompt_tokens=20, completion_tokens=10, fallback_used=True)

    snap = service.get_snapshot()
    assert snap.total_requests == 2
    assert snap.successful_requests == 2
    assert snap.failed_requests == 0
    assert snap.total_prompt_tokens == 70
    assert snap.total_completion_tokens == 40
    assert snap.total_tokens == 110
    assert snap.fallback_triggers_count == 1
    assert snap.average_latency_ms == 100.0
    # Because fallback_used > 0, health is DEGRADED
    assert snap.health_status == HealthStatus.DEGRADED
    assert snap.provider_breakdown["mock"] == 2


def test_impl_record_failure_and_health_status():
    service = ModelBackendObservabilityService()
    # 3 failures, 1 success -> 75% failure rate -> CRITICAL
    service.record_completion(provider="openai_compatible", duration_ms=50.0, prompt_tokens=10, completion_tokens=5)
    service.record_failure(provider="openai_compatible", error_type="TIMEOUT")
    service.record_failure(provider="openai_compatible", error_type="RATE_LIMIT")
    service.record_failure(provider="openai_compatible", error_type="AUTH")

    snap = service.get_snapshot()
    assert snap.total_requests == 4
    assert snap.successful_requests == 1
    assert snap.failed_requests == 3
    assert snap.health_status == HealthStatus.CRITICAL


def test_impl_policy_denials_and_reset():
    service = ModelBackendObservabilityService()
    service.record_policy_denial()
    service.record_policy_denial()

    snap = service.get_snapshot()
    assert snap.policy_denials == 2

    service.reset()
    snap_after = service.get_snapshot()
    assert snap_after.total_requests == 0
    assert snap_after.policy_denials == 0
    assert snap_after.health_status == HealthStatus.HEALTHY
