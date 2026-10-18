"""Focused Unit Tests for MCP Server Core Observability Subsystem (T-03137).

Covers:
- Metric snapshot creation and serialization
- Invariant validations (timestamp, bounds, math consistency)
- Health status computation state transitions
- Boundary values and failure modes
"""

import pytest
from aiosh_mcp.mcp_server_core_observability import (
    HealthStatus,
    McpCoreMetricsSnapshot,
    McpServerCoreObservabilityService,
)


def test_unit_observability_invariants_validation():
    # 1. Invalid empty timestamp
    with pytest.raises(ValueError, match="generated_at_utc cannot be empty"):
        snapshot = McpCoreMetricsSnapshot(
            generated_at_utc="",
            uptime_seconds=10.0,
            total_tools_registered=5,
            active_sessions_count=1,
            max_sessions_capacity=64,
            capacity_utilization_percent=1.5,
            total_dispatches=2,
            successful_dispatches=2,
            failed_dispatches=0,
            policy_denials=0,
            average_dispatch_latency_ms=10.0,
            health_status=HealthStatus.HEALTHY,
        )
        snapshot.validate()

    # 2. Inconsistent dispatch totals
    with pytest.raises(ValueError, match="total_dispatches .* != successful .* \\+ failed"):
        snapshot = McpCoreMetricsSnapshot(
            generated_at_utc="2026-10-18T12:00:00+00:00",
            uptime_seconds=10.0,
            total_tools_registered=5,
            active_sessions_count=1,
            max_sessions_capacity=64,
            capacity_utilization_percent=1.5,
            total_dispatches=10,
            successful_dispatches=2,
            failed_dispatches=0,  # 2 + 0 != 10
            policy_denials=0,
            average_dispatch_latency_ms=10.0,
            health_status=HealthStatus.HEALTHY,
        )
        snapshot.validate()

    # 3. Out-of-bounds capacity utilization
    with pytest.raises(ValueError, match="capacity_utilization_percent .* out of bounds"):
        snapshot = McpCoreMetricsSnapshot(
            generated_at_utc="2026-10-18T12:00:00+00:00",
            uptime_seconds=10.0,
            total_tools_registered=5,
            active_sessions_count=1,
            max_sessions_capacity=64,
            capacity_utilization_percent=150.0,
            total_dispatches=2,
            successful_dispatches=2,
            failed_dispatches=0,
            policy_denials=0,
            average_dispatch_latency_ms=10.0,
            health_status=HealthStatus.HEALTHY,
        )
        snapshot.validate()


def test_unit_health_status_transitions():
    service = McpServerCoreObservabilityService()

    # Normal conditions -> HEALTHY
    assert service.compute_health(capacity_pct=10.0, failure_rate_pct=0.0) == HealthStatus.HEALTHY

    # Capacity >= 85% -> DEGRADED
    assert service.compute_health(capacity_pct=86.0, failure_rate_pct=0.0) == HealthStatus.DEGRADED

    # Failure rate >= 5% -> DEGRADED
    assert service.compute_health(capacity_pct=10.0, failure_rate_pct=6.5) == HealthStatus.DEGRADED

    # Capacity >= 98% -> CRITICAL
    assert service.compute_health(capacity_pct=99.0, failure_rate_pct=0.0) == HealthStatus.CRITICAL

    # Failure rate >= 20% -> CRITICAL
    assert service.compute_health(capacity_pct=10.0, failure_rate_pct=25.0) == HealthStatus.CRITICAL


def test_unit_metrics_aggregation_accuracy():
    service = McpServerCoreObservabilityService()

    service.record_dispatch(success=True, duration_ms=10.0)
    service.record_dispatch(success=True, duration_ms=20.0)
    service.record_dispatch(success=False, duration_ms=30.0)

    snapshot = service.get_snapshot(tools_count=12, active_sessions=3, max_capacity=64)
    assert snapshot.total_dispatches == 3
    assert snapshot.successful_dispatches == 2
    assert snapshot.failed_dispatches == 1
    assert snapshot.average_dispatch_latency_ms == pytest.approx(20.0, 0.001)

    d = snapshot.to_dict()
    assert d["total_dispatches"] == 3
    assert d["successful_dispatches"] == 2
    assert d["health_status"] == "HEALTHY"
