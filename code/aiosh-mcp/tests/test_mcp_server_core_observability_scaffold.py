"""Scaffold tests for MCP Server Core Observability Subsystem (T-03135)."""

import pytest
from aiosh_mcp.mcp_server_core_observability import (
    HealthStatus,
    McpCoreMetricsSnapshot,
    McpServerCoreObservabilityService,
)


def test_observability_scaffold_types():
    assert HealthStatus.HEALTHY.value == "HEALTHY"
    assert HealthStatus.DEGRADED.value == "DEGRADED"
    assert HealthStatus.CRITICAL.value == "CRITICAL"


def test_observability_scaffold_service():
    service = McpServerCoreObservabilityService()
    assert service.total_dispatches == 0

    snapshot = service.get_snapshot(tools_count=10, active_sessions=2, max_capacity=64)
    assert snapshot.total_tools_registered == 10
    assert snapshot.active_sessions_count == 2
    assert snapshot.health_status == HealthStatus.HEALTHY
