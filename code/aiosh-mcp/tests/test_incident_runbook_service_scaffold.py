"""Scaffold tests for Incident Response Runbooks Core Service (T-02975)."""

import pytest

from aiosh_mcp.incident_runbook_data_model import RunbookCatalogSnapshot
from aiosh_mcp.incident_runbook_service import (
    StepExecutionStatus,
    RunbookExecutionStatus,
    StepExecutionRecord,
    RunbookExecutionSession,
    render_action_template,
    RUNBOOK_ERR_PARAMETER_NOT_FOUND,
    RUNBOOK_ERR_INVALID_TEMPLATE,
)


def test_incident_runbook_service_scaffold_types():
    assert StepExecutionStatus.PENDING.value == "pending"
    assert StepExecutionStatus.parse_status("running") == StepExecutionStatus.RUNNING
    assert StepExecutionStatus.parse_status("awaiting_confirmation") == StepExecutionStatus.AWAITING_CONFIRMATION

    assert RunbookExecutionStatus.PENDING.value == "pending"
    assert RunbookExecutionStatus.parse_status("completed") == RunbookExecutionStatus.COMPLETED
    assert RunbookExecutionStatus.parse_status("aborted") == RunbookExecutionStatus.ABORTED

    record = StepExecutionRecord(step_id="STEP-01", command_rendered="echo containment")
    assert record.step_id == "STEP-01"
    assert record.status == StepExecutionStatus.PENDING


def test_incident_runbook_service_template_interpolation():
    params = {"target_pid": "1337", "target_uid": "1000"}

    template = "aiosh run kill -STOP {target_pid}"
    rendered = render_action_template(template, params)
    assert rendered == "aiosh run kill -STOP 1337"

    # Missing parameter
    with pytest.raises(ValueError, match=RUNBOOK_ERR_PARAMETER_NOT_FOUND):
        render_action_template("aiosh isolate {missing_param}", params)

    # Injection characters in parameter
    bad_params = {"bad_param": "1337; rm -rf /"}
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_TEMPLATE):
        render_action_template("aiosh run kill {bad_param}", bad_params)


def test_incident_runbook_session_scaffold_init():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    malware_spec = baseline.get_runbook("RB-IR-MALWARE-01")
    assert malware_spec is not None

    params = {"target_pid": "4242", "target_uid": "1001"}
    session = RunbookExecutionSession.init_from_spec(malware_spec, "INC-2026-001", params)

    assert session.runbook_id == "RB-IR-MALWARE-01"
    assert session.incident_id == "INC-2026-001"
    assert session.status == RunbookExecutionStatus.PENDING
    assert len(session.step_records) == 3
    assert session.step_records[0].command_rendered == "aiosh run kill -STOP 4242"
    assert not session.is_terminal()
