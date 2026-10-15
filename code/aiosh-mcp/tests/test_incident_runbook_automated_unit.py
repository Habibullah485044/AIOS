"""Focused Unit Tests for Incident Response Runbooks Automated Tests (T-03017).

Validates boundaries, negative cases, invalid inputs, and primary failure modes.
"""

import pytest

from aiosh_mcp.incident_runbook_data_model import (
    RUNBOOK_ERR_BOUNDS_EXCEEDED,
    RUNBOOK_ERR_INVALID_TEMPLATE,
    RunbookCatalogSnapshot,
    RunbookPhase,
    RunbookStep,
    RunbookTargetSubstrate,
)
from aiosh_mcp.incident_runbook_service import (
    MAX_RUNBOOK_PARAMS_COUNT,
    RUNBOOK_ERR_INVALID_PARAM_VALUE,
    RUNBOOK_ERR_INVALID_TRANSITION,
    RunbookExecutionSession,
    RunbookExecutionStatus,
    StepExecutionStatus,
    validate_parameter_value,
)


def test_unit_boundary_parameter_bounds():
    # Exact max parameter length (256)
    max_val = "a" * 256
    assert validate_parameter_value("param", max_val) == max_val

    # Exceeding max parameter length (257) fails
    over_val = "a" * 257
    with pytest.raises(ValueError, match=RUNBOOK_ERR_BOUNDS_EXCEEDED):
        validate_parameter_value("param", over_val)

    # Empty parameter value fails
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_PARAM_VALUE):
        validate_parameter_value("param", "")


def test_unit_boundary_parameters_count():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    malware = baseline.get_runbook("RB-IR-MALWARE-01")
    assert malware is not None

    params = {f"param_{i}": "val" for i in range(MAX_RUNBOOK_PARAMS_COUNT + 1)}
    with pytest.raises(ValueError, match=RUNBOOK_ERR_BOUNDS_EXCEEDED):
        RunbookExecutionSession.init_from_spec(malware, "INC-OVERFLOW", params)


def test_unit_invalid_inputs_in_runbook_steps():
    # Step with invalid template (unclosed brace) raises during __post_init__
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_TEMPLATE):
        RunbookStep(
            id="STEP-BAD-01",
            title="Bad step",
            phase=RunbookPhase.CONTAINMENT,
            target=RunbookTargetSubstrate.PROCESS,
            action_template="aiosh proc freeze {target_pid",
            automated=True,
            requires_confirmation=False,
            timeout_seconds=15,
        )


def test_unit_primary_failure_mode_simulation():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    malware = baseline.get_runbook("RB-IR-MALWARE-01")
    assert malware is not None

    params = {"target_pid": "9000", "target_uid": "1000"}
    session = RunbookExecutionSession.init_from_spec(malware, "INC-FAIL-TEST", params)

    # Primary failure mode: simulated execution error
    st = session.advance_step(malware, simulate_success=False)
    assert st == StepExecutionStatus.FAILED
    assert session.status == RunbookExecutionStatus.FAILED
    assert session.is_terminal()

    rec = session.step_records[0]
    assert rec.status == StepExecutionStatus.FAILED
    assert rec.exit_code == 1
    assert rec.error_message is not None

    # Advancing failed session must fail closed
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_TRANSITION):
        session.advance_step(malware, simulate_success=True)


def test_unit_abort_transition_lifecycle():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    malware = baseline.get_runbook("RB-IR-MALWARE-01")
    assert malware is not None

    params = {"target_pid": "9001", "target_uid": "1000"}
    session = RunbookExecutionSession.init_from_spec(malware, "INC-ABORT-TEST", params)

    session.abort(reason="Operator aborted")
    assert session.status == RunbookExecutionStatus.ABORTED
    assert session.is_terminal()

    # Second abort raises
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_TRANSITION):
        session.abort("Second abort")

    # Advancing aborted session raises
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_TRANSITION):
        session.advance_step(malware, simulate_success=True)
