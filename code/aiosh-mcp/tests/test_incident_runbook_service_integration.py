"""Integration tests for Incident Response Runbooks Core Service (T-02978)."""

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
)


def test_integration_full_end_to_end_malware_containment():
    catalog = RunbookCatalogSnapshot.canonical_baseline()

    # 1. Alert arrives: Active malware executing
    incident_id = "INC-2026-ALERT-991"
    category = IncidentCategory.MALWARE_CONTAINMENT
    severity = IncidentSeverity.HIGH

    # 2. Matching runbook
    spec = match_runbook(catalog, category, severity)
    assert spec is not None
    assert spec.id == "RB-IR-MALWARE-01"

    # 3. Bind runtime parameters
    params = {"target_pid": "4567", "target_uid": "1005"}

    # 4. Initialize execution session
    session = RunbookExecutionSession.init_from_spec(spec, incident_id, params)
    assert session.status == RunbookExecutionStatus.PENDING
    assert len(session.step_records) == 3

    # 5. Execute step 1: Process freeze
    st1 = session.advance_step(spec, simulate_success=True)
    assert st1 == StepExecutionStatus.COMPLETED
    assert session.step_records[0].command_rendered == "aiosh run kill -STOP 4567"
    assert session.step_records[0].status == StepExecutionStatus.COMPLETED
    assert session.current_step_index == 1

    # 6. Execute step 2: Network quarantine
    st2 = session.advance_step(spec, simulate_success=True)
    assert st2 == StepExecutionStatus.COMPLETED
    assert session.step_records[1].command_rendered == "aiosh run iptables -A OUTPUT -m owner --uid-owner 1005 -j DROP"
    assert session.step_records[1].status == StepExecutionStatus.COMPLETED
    assert session.current_step_index == 2

    # 7. Execute step 3: Forensic audit checkpoint
    st3 = session.advance_step(spec, simulate_success=True)
    assert st3 == StepExecutionStatus.COMPLETED
    assert session.step_records[2].command_rendered == "aiosh audit checkpoint --reason 'Malware containment forensic snapshot'"
    assert session.step_records[2].status == StepExecutionStatus.COMPLETED
    assert session.current_step_index == 3

    # 8. Session closeout verification
    assert session.status == RunbookExecutionStatus.COMPLETED
    assert len(session.completed_at) > 0
    assert session.is_terminal()


def test_integration_cross_wire_format_continuation():
    catalog = RunbookCatalogSnapshot.canonical_baseline()
    access_spec = catalog.get_runbook("RB-IR-ACCESS-01")
    assert access_spec is not None

    params = {"grant_id": "CAP-REVOKE-99", "session_id": "SES-ROGUE-01"}

    # Step 1 performed in initial phase
    session = RunbookExecutionSession.init_from_spec(access_spec, "INC-UA-888", params)
    st1 = session.advance_step(access_spec, simulate_success=True)
    assert st1 == StepExecutionStatus.COMPLETED

    # Step 2 halts on confirmation gate
    st2_gate = session.advance_step(access_spec, simulate_success=True)
    assert st2_gate == StepExecutionStatus.AWAITING_CONFIRMATION

    # Cross-substrate persistence: serialize to JSON
    wire_json = session.to_json(indent=2)

    # Rehydrate session from wire format
    rehydrated = RunbookExecutionSession.from_json(wire_json)
    assert rehydrated.status == RunbookExecutionStatus.AWAITING_CONFIRMATION
    assert rehydrated.current_step_index == 1

    # Confirm and complete rehydrated session
    rehydrated.confirm_current_step()
    st2_complete = rehydrated.advance_step(access_spec, simulate_success=True)
    assert st2_complete == StepExecutionStatus.COMPLETED
    assert rehydrated.status == RunbookExecutionStatus.COMPLETED
