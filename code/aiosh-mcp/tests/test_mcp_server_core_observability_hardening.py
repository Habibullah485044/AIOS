"""Hardening tests for MCP Server Core Observability Subsystem (T-03140)."""

import pytest
from aiosh_mcp.mcp_server_core_observability import (
    HealthStatus,
    McpCoreMetricsSnapshot,
    McpServerCoreObservabilityService,
    sanitize_telemetry_text,
    MAX_TELEMETRY_TEXT_LEN,
)


def test_hardening_telemetry_text_sanitization():
    # 1. Strips NUL byte and control chars
    dirty = "label\x00with\x1fcontrols\x7f"
    clean = sanitize_telemetry_text(dirty)
    assert "\x00" not in clean
    assert "\x1f" not in clean
    assert clean == "labelwithcontrols"

    # 2. Strips zero-width unicode
    zero_width = "name\u200bhidden\ufefftext"
    clean_zw = sanitize_telemetry_text(zero_width)
    assert "\u200b" not in clean_zw
    assert "\ufeff" not in clean_zw
    assert clean_zw == "namehiddentext"

    # 3. Enforces MAX_TELEMETRY_TEXT_LEN
    oversized = "a" * 1000
    clean_over = sanitize_telemetry_text(oversized)
    assert len(clean_over) == MAX_TELEMETRY_TEXT_LEN


def test_hardening_division_by_zero_and_bounds():
    service = McpServerCoreObservabilityService()
    # Zero dispatches and zero capacity
    snapshot = service.get_snapshot(tools_count=0, active_sessions=0, max_capacity=0)
    assert snapshot.average_dispatch_latency_ms == 0.0
    assert snapshot.capacity_utilization_percent == 0.0
    assert snapshot.health_status == HealthStatus.HEALTHY
