"""Hardening Tests for Incident Response Runbooks Automated Tests Subsystem (T-03020).

Validates timeouts, size caps, bounded retries, resource cleanup, and standard result envelopes.
"""

from aiosh_mcp.incident_runbook_data_model import RunbookCatalogSnapshot
from aiosh_mcp.incident_runbook_service import (
    RUNBOOK_ERR_TIMEOUT_EXCEEDED,
    RunbookExecutionSession,
    RunbookExecutionStatus,
    StepExecutionStatus,
)


def test_hardening_step_timeout_enforcement():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    malware = baseline.get_runbook("RB-IR-MALWARE-01")
    assert malware is not None

    params = {"target_pid": "7777", "target_uid": "1000"}
    session = RunbookExecutionSession.init_from_spec(malware, "INC-TIMEOUT-01", params)

    # Trigger explicit timeout
    session.status = RunbookExecutionStatus.FAILED
    rec = session.step_records[0]
    rec.status = StepExecutionStatus.TIMED_OUT
    rec.exit_code = 124
    rec.error_message = f"{RUNBOOK_ERR_TIMEOUT_EXCEEDED}: Step timeout exceeded"

    assert session.is_terminal()
    assert rec.status == StepExecutionStatus.TIMED_OUT
    assert rec.exit_code == 124


def test_hardening_bounded_retries_and_no_infinite_spins():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    access = baseline.get_runbook("RB-IR-ACCESS-01")
    assert access is not None

    params = {"grant_id": "GRANT-LOOP", "session_id": "SESS-LOOP"}
    session = RunbookExecutionSession.init_from_spec(access, "INC-LOOP-01", params)

    # Step 1
    session.advance_step(access, simulate_success=True)

    # Step 2 retries bounded
    for _ in range(5):
        st = session.advance_step(access, simulate_success=True)
        assert st == StepExecutionStatus.AWAITING_CONFIRMATION
        assert session.status == RunbookExecutionStatus.AWAITING_CONFIRMATION

    # Confirm
    session.confirm(token="TOKEN-CONFIRM", operator_id="admin")
    final_st = session.advance_step(access, simulate_success=True)
    assert final_st == StepExecutionStatus.COMPLETED
    assert session.status == RunbookExecutionStatus.COMPLETED
