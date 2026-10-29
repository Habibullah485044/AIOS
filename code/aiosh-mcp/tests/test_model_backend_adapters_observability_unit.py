"""Unit tests for Model Backend Adapters Observability Subsystem (T-03237)."""

import pytest
from datetime import datetime, timezone
from aiosh_mcp.model_backend_adapters_observability import (
    HealthStatus,
    ModelBackendMetricsSnapshot,
    ModelBackendObservabilityService,
    sanitize_telemetry_text,
    MAX_TELEMETRY_TEXT_LEN,
)


def test_unit_text_sanitization():
    # Empty
    assert sanitize_telemetry_text("") == ""
    # Control characters and forbidden zero-width spaces
    bad_text = "provider\x00\x07name\u200b\ufeff\x1b[31m"
    clean = sanitize_telemetry_text(bad_text)
    assert "\x00" not in clean
    assert "\x07" not in clean
    assert "\u200b" not in clean
    assert "\ufeff" not in clean
    assert "providername" in clean

    # Length clamping
    oversized = "a" * (MAX_TELEMETRY_TEXT_LEN + 50)
    clamped = sanitize_telemetry_text(oversized)
    assert len(clamped) == MAX_TELEMETRY_TEXT_LEN


def test_unit_snapshot_validation_positive():
    snap = ModelBackendMetricsSnapshot(
        generated_at_utc=datetime.now(timezone.utc).isoformat(),
        uptime_seconds=100.5,
        total_requests=10,
        successful_requests=8,
        failed_requests=2,
        policy_denials=1,
        fallback_triggers_count=0,
        total_prompt_tokens=400,
        total_completion_tokens=200,
        total_tokens=600,
        average_latency_ms=150.2,
        health_status=HealthStatus.CRITICAL,  # 20% failure triggers DEGRADED or CRITICAL
        provider_breakdown={"mock": 8, "anthropic": 2},
    )
    snap.validate()
    d = snap.to_dict()
    assert d["total_requests"] == 10
    assert d["total_tokens"] == 600
    assert d["health_status"] == "CRITICAL"


def test_unit_snapshot_validation_negative_token_mismatch():
    snap = ModelBackendMetricsSnapshot(
        generated_at_utc=datetime.now(timezone.utc).isoformat(),
        uptime_seconds=10.0,
        total_requests=1,
        successful_requests=1,
        failed_requests=0,
        policy_denials=0,
        fallback_triggers_count=0,
        total_prompt_tokens=100,
        total_completion_tokens=50,
        total_tokens=999,  # Mismatch: 100 + 50 != 999
        average_latency_ms=50.0,
        health_status=HealthStatus.HEALTHY,
    )
    with pytest.raises(ValueError, match="total_tokens .* != prompt"):
        snap.validate()


def test_unit_snapshot_validation_negative_request_mismatch():
    snap = ModelBackendMetricsSnapshot(
        generated_at_utc=datetime.now(timezone.utc).isoformat(),
        uptime_seconds=10.0,
        total_requests=10,
        successful_requests=5,
        failed_requests=0,  # Mismatch: 5 + 0 != 10
        policy_denials=0,
        fallback_triggers_count=0,
        total_prompt_tokens=100,
        total_completion_tokens=50,
        total_tokens=150,
        average_latency_ms=50.0,
        health_status=HealthStatus.HEALTHY,
    )
    with pytest.raises(ValueError, match="total_requests .* != successful"):
        snap.validate()


def test_unit_snapshot_validation_negative_uptime():
    snap = ModelBackendMetricsSnapshot(
        generated_at_utc=datetime.now(timezone.utc).isoformat(),
        uptime_seconds=-5.0,  # Negative uptime
        total_requests=0,
        successful_requests=0,
        failed_requests=0,
        policy_denials=0,
        fallback_triggers_count=0,
        total_prompt_tokens=0,
        total_completion_tokens=0,
        total_tokens=0,
        average_latency_ms=0.0,
        health_status=HealthStatus.HEALTHY,
    )
    with pytest.raises(ValueError, match="uptime_seconds .* cannot be negative"):
        snap.validate()


def test_unit_service_health_status_thresholds():
    service = ModelBackendObservabilityService()

    # Initial state: 0 requests -> HEALTHY
    snap = service.get_snapshot()
    assert snap.health_status == HealthStatus.HEALTHY
    assert snap.average_latency_ms == 0.0

    # 19 successes, 1 failure -> 5% failure rate -> DEGRADED
    for _ in range(19):
        service.record_completion("mock", duration_ms=10.0, prompt_tokens=10, completion_tokens=5)
    service.record_failure("mock", "TIMEOUT")

    snap = service.get_snapshot()
    assert snap.total_requests == 20
    assert snap.failed_requests == 1
    assert snap.health_status == HealthStatus.DEGRADED

    # Add 10 more failures -> 11 failures out of 30 requests -> 36.6% failure rate -> CRITICAL
    for _ in range(10):
        service.record_failure("mock", "UNAVAILABLE")

    snap = service.get_snapshot()
    assert snap.health_status == HealthStatus.CRITICAL
