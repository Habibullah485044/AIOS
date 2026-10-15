"""Implementation tests for Incident Response Runbooks Observability in Python (T-03036)."""

import pytest

from aiosh_mcp.incident_runbook_data_model import RunbookCatalogSnapshot
from aiosh_mcp.incident_runbook_mcp import execute_runbook_action
from aiosh_mcp.incident_runbook_observability import (
    IROBS_ERR_VALIDATION,
    RunbookObservabilityService,
    RunbookObservabilitySnapshot,
)
from aiosh_mcp.incident_runbook_policy import RunbookEnforcementMode, RunbookSecurityPolicy


def test_observability_implementation_metrics_calculation() -> None:
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    policy = RunbookSecurityPolicy()

    snapshot = RunbookObservabilityService.generate_snapshot(
        catalog=baseline,
        active_sessions={"s-1": {}, "s-2": {}},
        policy=policy,
    )

    assert snapshot.total_catalog_runbooks == 2
    assert snapshot.total_executions == 4  # 2 catalog + 2 active
    assert snapshot.active_sessions_count == 2
    assert snapshot.active_sessions_utilization_percent == 2.0
    assert snapshot.is_healthy is True

    # Categories represented in baseline
    assert "malware_containment" in snapshot.executions_by_category
    assert "unauthorized_access" in snapshot.executions_by_category

    # Phases represented
    assert "containment" in snapshot.step_executions_by_phase
    assert "post_incident" in snapshot.step_executions_by_phase



def test_observability_implementation_mcp_stats_action() -> None:
    res = execute_runbook_action(action="stats")
    assert res["ok"] is True
    assert res["action"] == "stats"
    stats = res["stats"]
    assert stats["total_catalog_runbooks"] == 2
    assert stats["is_healthy"] is True
    assert "audit_id" in res



def test_observability_implementation_validation_bounds() -> None:
    snapshot = RunbookObservabilityService.generate_snapshot()

    # Valid snapshot passes
    RunbookObservabilityService.validate_snapshot(snapshot)

    # Invalid utilization percentage fails
    snapshot.active_sessions_utilization_percent = 20000.0
    with pytest.raises(ValueError, match=IROBS_ERR_VALIDATION):
        RunbookObservabilityService.validate_snapshot(snapshot)

