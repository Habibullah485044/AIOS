"""Focused unit tests for Incident Response Runbooks Observability in Python (T-03037).

Covers: valid input, invalid input, boundary values, and primary failure modes.
"""

import pytest

from aiosh_mcp.incident_runbook_data_model import RunbookCatalogSnapshot
from aiosh_mcp.incident_runbook_observability import (
    IROBS_ERR_VALIDATION,
    MAX_OBSERVABILITY_TEXT_LEN,
    RunbookObservabilityService,
    RunbookObservabilitySnapshot,
)
from aiosh_mcp.incident_runbook_policy import RunbookSecurityPolicy


def test_unit_observability_valid_baseline_and_custom_sessions() -> None:
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    policy = RunbookSecurityPolicy()

    # Zero active sessions
    snap_zero = RunbookObservabilityService.generate_snapshot(
        catalog=baseline, active_sessions={}, policy=policy
    )
    assert snap_zero.active_sessions_count == 0
    assert snap_zero.active_sessions_utilization_percent == 0.0
    assert snap_zero.total_executions == 2
    assert snap_zero.is_healthy is True

    # 50 active sessions
    dummy_50 = {f"s-{i}": {} for i in range(50)}
    snap_50 = RunbookObservabilityService.generate_snapshot(
        catalog=baseline, active_sessions=dummy_50, policy=policy
    )
    assert snap_50.active_sessions_count == 50
    assert snap_50.active_sessions_utilization_percent == 50.0
    assert snap_50.is_healthy is True


def test_unit_observability_boundary_utilization_and_health() -> None:
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    policy = RunbookSecurityPolicy(max_active_sessions=100)

    # Exact capacity boundary: 100 sessions = 100.0% utilization, still healthy
    dummy_100 = {f"s-{i}": {} for i in range(100)}
    snap_exact = RunbookObservabilityService.generate_snapshot(
        catalog=baseline, active_sessions=dummy_100, policy=policy
    )
    assert snap_exact.active_sessions_utilization_percent == 100.0
    assert snap_exact.is_healthy is True

    # Over-capacity boundary: 101 sessions -> unhealthy
    dummy_101 = {f"s-{i}": {} for i in range(101)}
    snap_over = RunbookObservabilityService.generate_snapshot(
        catalog=baseline, active_sessions=dummy_101, policy=policy
    )
    assert snap_over.is_healthy is False, "Over-capacity state must flag unhealthy"


def test_unit_observability_invalid_inputs_and_bounds() -> None:
    snapshot = RunbookObservabilityService.generate_snapshot()

    # Invalid: negative utilization
    snapshot.active_sessions_utilization_percent = -1.0
    with pytest.raises(ValueError, match=IROBS_ERR_VALIDATION):
        RunbookObservabilityService.validate_snapshot(snapshot)

    # Invalid: utilization > 10000.0
    snapshot.active_sessions_utilization_percent = 15000.0
    with pytest.raises(ValueError, match=IROBS_ERR_VALIDATION):
        RunbookObservabilityService.validate_snapshot(snapshot)


    # Reset utilization to valid
    snapshot.active_sessions_utilization_percent = 0.0

    # Invalid: oversized timestamp
    snapshot.generated_at_utc = "X" * (MAX_OBSERVABILITY_TEXT_LEN + 1)
    with pytest.raises(ValueError, match=IROBS_ERR_VALIDATION):
        RunbookObservabilityService.validate_snapshot(snapshot)


def test_unit_observability_primary_failure_mode_oversized_payload() -> None:
    snapshot = RunbookObservabilityService.generate_snapshot()

    # Inject huge number of dummy status keys to exceed MAX_OBSERVABILITY_PAYLOAD_BYTES
    for i in range(2000):
        snapshot.executions_by_status[f"status-{i}"] = i

    with pytest.raises(ValueError, match=IROBS_ERR_VALIDATION):
        RunbookObservabilityService.validate_snapshot(snapshot)
