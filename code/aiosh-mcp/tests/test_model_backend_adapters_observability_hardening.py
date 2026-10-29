"""Hardening tests for Model Backend Adapters Observability Subsystem (T-03240)."""

import pytest
from aiosh_mcp.model_backend_adapters_observability import (
    HealthStatus,
    ModelBackendObservabilityService,
    MAX_TRACKED_PROVIDERS,
    MAX_DURATION_MS,
    MAX_TOKENS_PER_RECORD,
)


def test_hardening_provider_capacity_bounds():
    service = ModelBackendObservabilityService()
    # Record completions across more providers than MAX_TRACKED_PROVIDERS
    for i in range(MAX_TRACKED_PROVIDERS + 10):
        service.record_completion(f"provider_{i}", duration_ms=10.0, prompt_tokens=5, completion_tokens=5)

    snap = service.get_snapshot()
    # Distinct provider keys should not exceed MAX_TRACKED_PROVIDERS + 1 (including 'other')
    assert len(snap.provider_breakdown) <= MAX_TRACKED_PROVIDERS + 1
    assert "other" in snap.provider_breakdown
    assert snap.provider_breakdown["other"] == 10


def test_hardening_clamping_and_bounds():
    service = ModelBackendObservabilityService()

    # Extreme positive values
    service.record_completion("mock", duration_ms=999_999_999.0, prompt_tokens=999_999_999, completion_tokens=999_999_999)
    snap = service.get_snapshot()
    assert snap.average_latency_ms == MAX_DURATION_MS
    assert snap.total_prompt_tokens == MAX_TOKENS_PER_RECORD
    assert snap.total_completion_tokens == MAX_TOKENS_PER_RECORD

    # Negative values
    service.reset()
    service.record_completion("mock", duration_ms=-50.0, prompt_tokens=-10, completion_tokens=-20)
    snap_neg = service.get_snapshot()
    assert snap_neg.average_latency_ms == 0.0
    assert snap_neg.total_tokens == 0
    assert snap_neg.total_prompt_tokens == 0
    assert snap_neg.total_completion_tokens == 0


def test_hardening_thread_safety_concurrency():
    import threading

    service = ModelBackendObservabilityService()

    def worker():
        for _ in range(50):
            service.record_completion("mock", duration_ms=10.0, prompt_tokens=2, completion_tokens=3)
            service.record_failure("mock", "TIMEOUT")

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    snap = service.get_snapshot()
    assert snap.total_requests == 400
    assert snap.successful_requests == 200
    assert snap.failed_requests == 200
    assert snap.total_tokens == 1000  # 200 * 5
    assert snap.health_status == HealthStatus.CRITICAL
