"""Automated Test Suite for Incident Response Runbooks — MCP Substrate (T-03016 Implementation).

Contract: docs/tasks/evidence/T-03014-spec.md.
Implements automated vectors AUTORUNBOOK1..AUTORUNBOOK10.
"""

from __future__ import annotations

import json
import os
import tempfile
import pytest

from aiosh_mcp._dispatch import conn_ctx
from aiosh_mcp.incident_runbook_data_model import (
    RunbookCatalogSnapshot,
    IncidentCategory,
    IncidentSeverity,
    RUNBOOK_ERR_BOUNDS_EXCEEDED,
)
from aiosh_mcp.incident_runbook_service import (
    RunbookExecutionSession,
    RunbookExecutionStatus,
    StepExecutionStatus,
    RUNBOOK_ERR_SESSION_NOT_FOUND,
    RUNBOOK_ERR_INVALID_TRANSITION,
    RUNBOOK_ERR_INVALID_PARAM_VALUE,
    validate_parameter_value,
)
from aiosh_mcp.runbook_config import (
    RunbookConfig,
    DEFAULT_CATALOG_PATH,
    DEFAULT_MAX_ACTIVE_SESSIONS,
    ENV_RUNBOOK_MAX_SESSIONS,
    RUNBOOKCONF_ERR_PATH_TRAVERSAL,
    resolve_runbook_config,
    safe_resolve_runbook_config,
)
from aiosh_mcp.incident_runbook_mcp import (
    execute_runbook_action,
    execute_scan_action,
)


def test_autorunbook1_catalog_snapshot_integrity():
    """AUTORUNBOOK1: Catalog Snapshot & Spec Invariant Validation."""
    snapshot = RunbookCatalogSnapshot.canonical_baseline()
    assert len(snapshot.runbooks) >= 2

    malware = snapshot.get_runbook("RB-IR-MALWARE-01")
    assert malware is not None
    assert malware.category == IncidentCategory.MALWARE_CONTAINMENT
    assert malware.severity == IncidentSeverity.HIGH
    assert len(malware.steps) == 3

    access = snapshot.get_runbook("RB-IR-ACCESS-01")
    assert access is not None
    assert access.category == IncidentCategory.UNAUTHORIZED_ACCESS
    assert access.severity == IncidentSeverity.CRITICAL
    # Step 2 requires confirmation
    assert access.steps[1].requires_confirmation is True


def test_autorunbook2_state_machine_lifecycle():
    """AUTORUNBOOK2: Session State Machine Transitions."""
    snapshot = RunbookCatalogSnapshot.canonical_baseline()
    malware = snapshot.get_runbook("RB-IR-MALWARE-01")

    session = RunbookExecutionSession.init_from_spec(
        malware,
        "INC-2026-AUTO-01",
        {"target_pid": "1001", "target_uid": "1001"},
    )
    assert session.status == RunbookExecutionStatus.PENDING
    assert session.current_step_index == 0

    # Advance step 1
    s1 = session.advance_step(malware, simulate_success=True)
    assert s1 == StepExecutionStatus.COMPLETED
    assert session.status == RunbookExecutionStatus.RUNNING
    assert session.current_step_index == 1

    # Advance step 2
    s2 = session.advance_step(malware, simulate_success=True)
    assert s2 == StepExecutionStatus.COMPLETED
    assert session.current_step_index == 2

    # Advance step 3 (final)
    s3 = session.advance_step(malware, simulate_success=True)
    assert s3 == StepExecutionStatus.COMPLETED
    assert session.status == RunbookExecutionStatus.COMPLETED

    # Advancing completed session must fail closed
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_TRANSITION):
        session.advance_step(malware, simulate_success=True)


def test_autorunbook3_high_risk_operator_confirmation_gate():
    """AUTORUNBOOK3: High-Risk Operator Confirmation Gate."""
    snapshot = RunbookCatalogSnapshot.canonical_baseline()
    access = snapshot.get_runbook("RB-IR-ACCESS-01")

    session = RunbookExecutionSession.init_from_spec(
        access,
        "INC-2026-AUTO-02",
        {"grant_id": "grant-compromised-99", "session_id": "sess-malicious-101"},
    )
    # Step 1: automated
    s1 = session.advance_step(access, simulate_success=True)
    assert s1 == StepExecutionStatus.COMPLETED

    # Step 2: requires confirmation
    s2 = session.advance_step(access, simulate_success=True)
    assert s2 == StepExecutionStatus.AWAITING_CONFIRMATION
    assert session.status == RunbookExecutionStatus.AWAITING_CONFIRMATION

    # Trying to advance again without confirming stays awaiting confirmation
    s2_retry = session.advance_step(access, simulate_success=True)
    assert s2_retry == StepExecutionStatus.AWAITING_CONFIRMATION

    # Grant confirmation and advance
    session.confirm(token="CONFIRM-TOKEN-123", operator_id="admin")
    assert session.operator_confirmed is True

    s2_confirmed = session.advance_step(access, simulate_success=True)
    assert s2_confirmed == StepExecutionStatus.COMPLETED
    assert session.current_step_index == 2


def test_autorunbook4_parameter_extraction_and_injection_defense():
    """AUTORUNBOOK4: Parameter Extraction & Injection Defense."""
    # Valid parameter
    assert validate_parameter_value("target_pid", "4096") == "4096"

    # Reject empty
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_PARAM_VALUE):
        validate_parameter_value("target_pid", "")

    # Reject path traversal
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_PARAM_VALUE):
        validate_parameter_value("target_pid", "../etc/passwd")

    # Reject shell metacharacters / injection
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_PARAM_VALUE):
        validate_parameter_value("target_pid", "4096; rm -rf /")

    # Reject length > 256
    with pytest.raises(ValueError, match=RUNBOOK_ERR_BOUNDS_EXCEEDED):
        validate_parameter_value("target_pid", "a" * 257)


def test_autorunbook5_forensic_file_pattern_scanning():
    """AUTORUNBOOK5: Forensic File Pattern Scanning (ripgrep-grade)."""
    with tempfile.TemporaryDirectory() as td:
        log_file = os.path.join(td, "incident.log")
        with open(log_file, "w", encoding="utf-8") as f:
            f.write("Line 1: Normal event\nLine 2: SYNTHETIC_MALWARE_HASH_TOKEN_882\nLine 3: End\n")

        res = execute_scan_action(
            action="files",
            target=td,
            pattern="SYNTHETIC_MALWARE_HASH",
            max_depth=3,
        )
        assert res["ok"] is True
        assert res["matches_count"] == 1
        assert "incident.log" in res["matches"][0]["file"]
        assert "SYNTHETIC_MALWARE_HASH_TOKEN_882" in res["matches"][0]["line"]


def test_autorunbook6_network_and_web_scanning_hygiene():
    """AUTORUNBOOK6: Network & Web Port Scanning Hygiene."""
    # Scan net on localhost
    res_net = execute_scan_action(
        action="net",
        target="127.0.0.1",
        ports="59999",
        timeout_ms=100,
    )
    assert res_net["ok"] is True
    assert res_net["target"] == "127.0.0.1"

    # Reject path traversal in target via execute_scan_action envelope
    res_err = execute_scan_action(action="net", target="../evil.host")
    assert res_err["ok"] is False
    assert "SEC_ERR_INVALID_TARGET" in res_err["error"]

    # Reject directly via validator
    from aiosh_mcp.incident_runbook_mcp import validate_scan_target
    with pytest.raises(ValueError, match="SEC_ERR_INVALID_TARGET"):
        validate_scan_target("../evil.host")


def test_autorunbook7_config_ladder_precedence():
    """AUTORUNBOOK7: 4-Level Configuration Ladder Resolution."""
    # Level 1 override beats Level 4 default
    cfg = resolve_runbook_config(max_active_sessions=750)
    assert cfg.max_active_sessions == 750
    assert cfg.sources["max_active_sessions"] == "argument"
    assert cfg.sources["catalog_path"] == "default"


def test_autorunbook8_dynamic_concurrency_and_eviction():
    """AUTORUNBOOK8: Dynamic Concurrency & Active Session Eviction."""
    old_env = os.environ.get(ENV_RUNBOOK_MAX_SESSIONS)
    try:
        os.environ[ENV_RUNBOOK_MAX_SESSIONS] = "2"
        s1 = execute_runbook_action(
            action="start",
            runbook_id="RB-IR-MALWARE-01",
            incident_id="INC-AUTO-CAP-1",
            parameters={"target_pid": "100", "target_uid": "100"},
        )
        s2 = execute_runbook_action(
            action="start",
            runbook_id="RB-IR-MALWARE-01",
            incident_id="INC-AUTO-CAP-2",
            parameters={"target_pid": "200", "target_uid": "200"},
        )
        # Starting 3rd session must evict 1st session under limit=2
        s3 = execute_runbook_action(
            action="start",
            runbook_id="RB-IR-MALWARE-01",
            incident_id="INC-AUTO-CAP-3",
            parameters={"target_pid": "300", "target_uid": "300"},
        )
        st1 = execute_runbook_action(action="status", session_id=s1["session_id"])
        assert st1["ok"] is False  # Evicted
        st3 = execute_runbook_action(action="status", session_id=s3["session_id"])
        assert st3["ok"] is True   # Retained
    finally:
        if old_env is None:
            os.environ.pop(ENV_RUNBOOK_MAX_SESSIONS, None)
        else:
            os.environ[ENV_RUNBOOK_MAX_SESSIONS] = old_env


def test_autorunbook9_proof_of_restraint_audit_trail():
    """AUTORUNBOOK9: Proof-of-Restraint Authorization & Audit Trail (Invariant I-2)."""
    with conn_ctx() as conn:
        initial_count = conn.execute("SELECT count(*) FROM audit_ring").fetchone()[0]

    res = execute_runbook_action(action="config")
    assert res["ok"] is True
    audit_id = res.get("audit_id")
    assert audit_id is not None
    assert audit_id > 0

    with conn_ctx() as conn:
        final_count = conn.execute("SELECT count(*) FROM audit_ring").fetchone()[0]
        assert final_count >= initial_count + 1


def test_autorunbook10_fail_closed_result_envelopes():
    """AUTORUNBOOK10: Standardized Fail-Closed Result Envelopes."""
    # Safe resolution envelope catches traversal and returns structured error envelope
    res = safe_resolve_runbook_config(config_path="../traversal.json")
    assert res["ok"] is False
    assert res["error_code"] == RUNBOOKCONF_ERR_PATH_TRAVERSAL
    assert res["config"]["catalog_path"] == DEFAULT_CATALOG_PATH
