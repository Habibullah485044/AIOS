"""Implementation tests for MCP Server Core Observability Subsystem (T-03136)."""

import pytest
from aiosh_mcp.mcp_server_core_observability import (
    HealthStatus,
    McpCoreMetricsSnapshot,
    McpServerCoreObservabilityService,
)


def test_observability_dispatch_recording():
    service = McpServerCoreObservabilityService()

    # Record 10 successes
    for _ in range(10):
        service.record_dispatch(success=True, duration_ms=12.5)

    # Record 2 failures
    for _ in range(2):
        service.record_dispatch(success=False, duration_ms=25.0)

    # Record 1 policy denial
    service.record_policy_denial()

    snapshot = service.get_snapshot(tools_count=16, active_sessions=4, max_capacity=64)
    assert snapshot.total_dispatches == 12
    assert snapshot.successful_dispatches == 10
    assert snapshot.failed_dispatches == 2
    assert snapshot.policy_denials == 1
    assert snapshot.total_tools_registered == 16
    assert snapshot.active_sessions_count == 4
    assert snapshot.capacity_utilization_percent == 6.25
    assert snapshot.health_status == HealthStatus.HEALTHY
    assert snapshot.average_dispatch_latency_ms > 0.0


def test_observability_health_degradation_on_capacity():
    service = McpServerCoreObservabilityService()
    # 90% capacity should degrade health
    snapshot = service.get_snapshot(tools_count=5, active_sessions=90, max_capacity=100)
    assert snapshot.health_status == HealthStatus.DEGRADED

    # 99% capacity should mark critical
    snapshot_crit = service.get_snapshot(tools_count=5, active_sessions=99, max_capacity=100)
    assert snapshot_crit.health_status == HealthStatus.CRITICAL
