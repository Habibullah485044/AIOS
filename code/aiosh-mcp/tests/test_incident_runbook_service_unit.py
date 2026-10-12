"""Unit tests for Incident Response Runbooks Core Service (T-02977)."""

import pytest

from aiosh_mcp.incident_runbook_data_model import (
    RunbookCatalogSnapshot,
    IncidentCategory,
    IncidentSeverity,
)
from aiosh_mcp.incident_runbook_service import (
    StepExecutionStatus,
    RunbookExecutionStatus,
    RunbookExecutionSession,
    match_runbook,
    RUNBOOK_ERR_INVALID_TRANSITION,
    RUNBOOK_ERR_TIMEOUT_EXCEEDED,
)


def test_session_lifecycle_normal_progression():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    malware_spec = baseline.get_runbook("RB-IR-MALWARE-01")
    assert malware_spec is not None

    params = {"target_pid": "9999", "target_uid": "1002"}
    session = RunbookExecutionSession.init_from_spec(malware_spec, "INC-NORM-01", params)
    assert session.status == RunbookExecutionStatus.PENDING
    assert session.current_step_index == 0

    # Step 1: Automated
    st1 = session.advance_step(malware_spec, simulate_success=True)
    assert st1 == StepExecutionStatus.COMPLETED
    assert session.current_step_index == 1
    assert session.status == RunbookExecutionStatus.RUNNING

    # Step 2: Automated
    st2 = session.advance_step(malware_spec, simulate_success=True)
    assert st2 == StepExecutionStatus.COMPLETED
    assert session.current_step_index == 2

    # Step 3: Automated
    st3 = session.advance_step(malware_spec, simulate_success=True)
    assert st3 == StepExecutionStatus.COMPLETED
    assert session.current_step_index == 3
    assert session.status == RunbookExecutionStatus.COMPLETED
    assert len(session.completed_at) > 0
    assert session.is_terminal()

    # Advancing terminal session fails
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_TRANSITION):
        session.advance_step(malware_spec, simulate_success=True)


def test_session_confirmation_gate_enforcement():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    access_spec = baseline.get_runbook("RB-IR-ACCESS-01")
    assert access_spec is not None

    params = {"grant_id": "GRANT-123", "session_id": "SESS-456"}
    session = RunbookExecutionSession.init_from_spec(access_spec, "INC-CONF-01", params)

    # Step 1: Automated revocation
    st1 = session.advance_step(access_spec, simulate_success=True)
    assert st1 == StepExecutionStatus.COMPLETED
    assert session.current_step_index == 1

    # Step 2: Requires confirmation!
    st2_attempt1 = session.advance_step(access_spec, simulate_success=True)
    assert st2_attempt1 == StepExecutionStatus.AWAITING_CONFIRMATION
    assert session.status == RunbookExecutionStatus.AWAITING_CONFIRMATION
    assert session.current_step_index == 1

    # Attempting to advance again without confirmation remains awaiting
    st2_attempt2 = session.advance_step(access_spec, simulate_success=True)
    assert st2_attempt2 == StepExecutionStatus.AWAITING_CONFIRMATION

    # Provide confirmation
    session.confirm_current_step()
    assert session.status == RunbookExecutionStatus.RUNNING

    # Now execute Step 2
    st2_executed = session.advance_step(access_spec, simulate_success=True)
    assert st2_executed == StepExecutionStatus.COMPLETED
    assert session.status == RunbookExecutionStatus.COMPLETED


def test_session_abort_handling():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    malware_spec = baseline.get_runbook("RB-IR-MALWARE-01")
    assert malware_spec is not None

    params = {"target_pid": "100", "target_uid": "1000"}
    session = RunbookExecutionSession.init_from_spec(malware_spec, "INC-ABORT-01", params)

    session.abort("Operator requested immediate stop")
    assert session.status == RunbookExecutionStatus.ABORTED
    assert session.step_records[0].status == StepExecutionStatus.SKIPPED
    assert session.is_terminal()

    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_TRANSITION):
        session.advance_step(malware_spec, simulate_success=True)


def test_session_failure_and_timeout_handling():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    malware_spec = baseline.get_runbook("RB-IR-MALWARE-01")
    assert malware_spec is not None

    params = {"target_pid": "100", "target_uid": "1000"}

    session_fail = RunbookExecutionSession.init_from_spec(malware_spec, "INC-FAIL-01", params)
    st_fail = session_fail.advance_step(malware_spec, simulate_success=False)
    assert st_fail == StepExecutionStatus.FAILED
    assert session_fail.status == RunbookExecutionStatus.FAILED
    assert session_fail.is_terminal()

    session_timeout = RunbookExecutionSession.init_from_spec(malware_spec, "INC-TO-01", params)
    session_timeout.timeout_current()
    assert session_timeout.status == RunbookExecutionStatus.FAILED
    assert session_timeout.step_records[0].status == StepExecutionStatus.TIMED_OUT
    assert session_timeout.step_records[0].exit_code == 124


def test_catalog_matching_and_json_roundtrip():
    catalog = RunbookCatalogSnapshot.canonical_baseline()

    matched_mw = match_runbook(catalog, IncidentCategory.MALWARE_CONTAINMENT, IncidentSeverity.HIGH)
    assert matched_mw is not None
    assert matched_mw.id == "RB-IR-MALWARE-01"

    matched_ua = match_runbook(catalog, "unauthorized_access", "critical")
    assert matched_ua is not None
    assert matched_ua.id == "RB-IR-ACCESS-01"

    params = {"target_pid": "555", "target_uid": "555"}
    session = RunbookExecutionSession.init_from_spec(matched_mw, "INC-JSON-01", params)

    json_str = session.to_json(indent=2)
    rehydrated = RunbookExecutionSession.from_json(json_str)

    assert session.session_id == rehydrated.session_id
    assert len(session.step_records) == len(rehydrated.step_records)
    assert session.status == rehydrated.status
