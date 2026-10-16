"""Hardening tests for Incident Response Runbooks Observability Subsystem (T-03040)."""

from pathlib import Path
import os
import pytest

from aiosh_mcp.incident_runbook_data_model import RunbookCatalogSnapshot
from aiosh_mcp.incident_runbook_policy import RunbookSecurityPolicy
from aiosh_mcp.incident_runbook_observability import (
    ObservabilityResultEnvelope,
    RunbookObservabilityService,
    RunbookObservabilitySnapshot,
    IROBS_ERR_VALIDATION,
    MAX_OBSERVABILITY_ACTIVE_SESSIONS,
    MAX_OBSERVABILITY_PAYLOAD_BYTES,
)
from aiosh_mcp.incident_runbook_mcp import execute_runbook_core


def test_hardening_observability_result_envelope_success_and_failure():
    catalog = RunbookCatalogSnapshot.canonical_baseline()
    policy = RunbookSecurityPolicy()

    # 1. Success case
    env_ok = RunbookObservabilityService.generate_snapshot_safe(
        catalog=catalog,
        active_sessions={"sess-1": {}, "sess-2": {}},
        policy=policy,
    )
    assert env_ok.ok is True
    assert env_ok.snapshot is not None
    assert env_ok.error_code is None
    assert env_ok.audit_row_required is False
    assert env_ok.snapshot.active_sessions_count == 2
    assert env_ok.snapshot.is_healthy is True

    # 2. Failure case with excessive sessions exceeding sanity cap
    fake_huge_sessions = {f"s_{i}": {} for i in range(MAX_OBSERVABILITY_ACTIVE_SESSIONS + 1)}
    env_err = RunbookObservabilityService.generate_snapshot_safe(
        catalog=catalog,
        active_sessions=fake_huge_sessions,
        policy=policy,
    )
    assert env_err.ok is False
    assert env_err.snapshot is None
    assert env_err.error_code == IROBS_ERR_VALIDATION
    assert env_err.audit_row_required is True
    assert "exceeds sanity limit" in env_err.error_message


def test_hardening_observability_degraded_capacity_adr0035_af2():
    catalog = RunbookCatalogSnapshot.canonical_baseline()
    policy = RunbookSecurityPolicy(max_active_sessions=5)

    # Over capacity: 8 active sessions > 5
    active = {f"s_{i}": {} for i in range(8)}
    env = RunbookObservabilityService.generate_snapshot_safe(
        catalog=catalog,
        active_sessions=active,
        policy=policy,
    )
    assert env.ok is True
    assert env.snapshot is not None
    snap = env.snapshot
    assert snap.is_healthy is False
    assert snap.active_sessions_count == 8
    assert snap.active_sessions_utilization_percent == 160.0
    # Honest audit row required per ADR-0035 AF-2
    assert env.audit_row_required is True
    assert "exceeds configured policy limit" in env.error_message


def test_hardening_observability_atomic_persistence_and_cleanup(tmp_path: Path):
    catalog = RunbookCatalogSnapshot.canonical_baseline()
    policy = RunbookSecurityPolicy()
    snapshot = RunbookObservabilityService.generate_snapshot(catalog=catalog, policy=policy)

    target_file = tmp_path / "test_obs_snapshot.json"

    # 1. Atomic write & read
    RunbookObservabilityService.save_snapshot_atomic(target_file, snapshot)
    assert target_file.exists()

    loaded = RunbookObservabilityService.load_snapshot_file(target_file)
    assert loaded.total_catalog_runbooks == snapshot.total_catalog_runbooks
    assert loaded.active_sessions_count == snapshot.active_sessions_count

    # Verify temp file does not remain
    temp_pattern = f"{target_file.name}.tmp.{os.getpid()}"
    assert not (tmp_path / temp_pattern).exists(), "Temp file must be cleaned up"


def test_hardening_observability_payload_and_bounds_rejection():
    catalog = RunbookCatalogSnapshot.canonical_baseline()
    policy = RunbookSecurityPolicy()
    snapshot = RunbookObservabilityService.generate_snapshot(catalog=catalog, policy=policy)

    # 1. Invalid float bounds
    snapshot.active_sessions_utilization_percent = -1.0
    with pytest.raises(ValueError, match="active_sessions_utilization_percent out of bounds"):
        RunbookObservabilityService.validate_snapshot(snapshot)

    snapshot.active_sessions_utilization_percent = 20_000.0
    with pytest.raises(ValueError, match="active_sessions_utilization_percent out of bounds"):
        RunbookObservabilityService.validate_snapshot(snapshot)

    # 2. Excess map entries
    snapshot.active_sessions_utilization_percent = 50.0
    snapshot.executions_by_status = {f"status_{i}": i for i in range(200)}
    with pytest.raises(ValueError, match="executions_by_status exceeds max entries"):
        RunbookObservabilityService.validate_snapshot(snapshot)


def test_hardening_observability_mcp_stats_dispatch():
    res = execute_runbook_core(action="stats")
    assert res["ok"] is True
    assert res["action"] == "stats"
    assert "stats" in res
    assert "total_catalog_runbooks" in res["stats"]
    assert "audit_row_required" in res
