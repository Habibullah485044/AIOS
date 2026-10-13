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
    validate_parameter_value,
    RUNBOOK_ERR_INVALID_TRANSITION,
    RUNBOOK_ERR_TIMEOUT_EXCEEDED,
    RUNBOOK_ERR_INVALID_PARAM_VALUE,
    RUNBOOK_ERR_BOUNDS_EXCEEDED,
    RUNBOOK_ERR_MISSING_CONFIRMATION,
    MAX_RUNBOOK_PARAM_LEN,
    MAX_RUNBOOK_PARAMS_COUNT,
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


def test_parameter_value_hardening():
    # Valid values
    assert validate_parameter_value("pid", "12345") == "12345"
    assert validate_parameter_value("path", "/var/log/audit.log") == "/var/log/audit.log"
    assert validate_parameter_value("ip", "192.168.1.1:8080") == "192.168.1.1:8080"

    # Empty
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_PARAM_VALUE):
        validate_parameter_value("pid", "")

    # Path traversal
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_PARAM_VALUE):
        validate_parameter_value("path", "../etc/passwd")

    # Command injection metacharacters
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_PARAM_VALUE):
        validate_parameter_value("pid", "1234; rm -rf")
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_PARAM_VALUE):
        validate_parameter_value("pid", "1234 | sh")
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_PARAM_VALUE):
        validate_parameter_value("pid", "1234 `id`")
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_PARAM_VALUE):
        validate_parameter_value("pid", "$(cat /etc/shadow)")

    # Exceed max length
    long_val = "A" * (MAX_RUNBOOK_PARAM_LEN + 1)
    with pytest.raises(ValueError, match=RUNBOOK_ERR_BOUNDS_EXCEEDED):
        validate_parameter_value("long", long_val)


def test_parameter_count_bounds_hardening():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    spec = baseline.get_runbook("RB-IR-MALWARE-01")

    too_many_params = {f"param_{i}": f"val_{i}" for i in range(33)}
    with pytest.raises(ValueError, match=RUNBOOK_ERR_BOUNDS_EXCEEDED):
        RunbookExecutionSession.init_from_spec(spec, "INC-TOO-MANY", too_many_params)


def test_confirmation_token_hardening():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    access_spec = baseline.get_runbook("RB-IR-ACCESS-01")

    params = {"grant_id": "GRANT-1", "session_id": "SES-1"}
    session = RunbookExecutionSession.init_from_spec(access_spec, "INC-CONF-VAL", params)
    session.advance_step(access_spec, simulate_success=True)
    session.advance_step(access_spec, simulate_success=True)
    assert session.status == RunbookExecutionStatus.AWAITING_CONFIRMATION

    # Invalid operator ID
    with pytest.raises(ValueError, match=RUNBOOK_ERR_MISSING_CONFIRMATION):
        session.confirm_current_step(operator_id="", token="valid-token")

    # Invalid token
    with pytest.raises(ValueError, match=RUNBOOK_ERR_MISSING_CONFIRMATION):
        session.confirm_current_step(operator_id="operator-alice", token="")

    # Valid confirmation
    session.confirm_current_step(operator_id="operator-alice", token="sig-verified-99")
    assert session.status == RunbookExecutionStatus.RUNNING
