//! Integration tests for Incident Response Runbooks Core Service (T-02978).

use std::collections::HashMap;
use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_service::*;

#[test]
fn test_integration_full_end_to_end_malware_containment() {
    let catalog = RunbookCatalogSnapshot::canonical_baseline();

    // 1. Alert arrives: Active malware executing
    let incident_id = "INC-2026-ALERT-991";
    let category = IncidentCategory::MalwareContainment;
    let severity = IncidentSeverity::High;

    // 2. Matching runbook
    let spec = match_runbook(&catalog, category, severity).expect("Matching runbook required");
    assert_eq!(spec.id, "RB-IR-MALWARE-01");

    // 3. Bind runtime parameters
    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "4567".to_string());
    params.insert("target_uid".to_string(), "1005".to_string());

    // 4. Initialize execution session
    let mut session = RunbookExecutionSession::init_from_spec(spec, incident_id, params).unwrap();
    assert_eq!(session.status, RunbookExecutionStatus::Pending);
    assert_eq!(session.step_records.len(), 3);

    // 5. Execute step 1: Process freeze
    let step1_res = session.advance_step(spec, true).unwrap();
    assert_eq!(step1_res, StepExecutionStatus::Completed);
    assert_eq!(session.step_records[0].command_rendered, "aiosh run kill -STOP 4567");
    assert_eq!(session.step_records[0].status, StepExecutionStatus::Completed);
    assert_eq!(session.current_step_index, 1);

    // 6. Execute step 2: Network quarantine
    let step2_res = session.advance_step(spec, true).unwrap();
    assert_eq!(step2_res, StepExecutionStatus::Completed);
    assert_eq!(session.step_records[1].command_rendered, "aiosh run iptables -A OUTPUT -m owner --uid-owner 1005 -j DROP");
    assert_eq!(session.step_records[1].status, StepExecutionStatus::Completed);
    assert_eq!(session.current_step_index, 2);

    // 7. Execute step 3: Forensic audit checkpoint
    let step3_res = session.advance_step(spec, true).unwrap();
    assert_eq!(step3_res, StepExecutionStatus::Completed);
    assert_eq!(session.step_records[2].command_rendered, "aiosh audit checkpoint --reason 'Malware containment forensic snapshot'");
    assert_eq!(session.step_records[2].status, StepExecutionStatus::Completed);
    assert_eq!(session.current_step_index, 3);

    // 8. Session closeout verification
    assert_eq!(session.status, RunbookExecutionStatus::Completed);
    assert!(!session.completed_at.is_empty());
    assert!(session.is_terminal());
}

#[test]
fn test_integration_cross_wire_format_continuation() {
    let catalog = RunbookCatalogSnapshot::canonical_baseline();
    let access_spec = catalog.get_runbook("RB-IR-ACCESS-01").unwrap();

    let mut params = HashMap::new();
    params.insert("grant_id".to_string(), "CAP-REVOKE-99".to_string());
    params.insert("session_id".to_string(), "SES-ROGUE-01".to_string());

    // Step 1 performed in initial phase
    let mut session = RunbookExecutionSession::init_from_spec(access_spec, "INC-UA-888", params).unwrap();
    let st1 = session.advance_step(access_spec, true).unwrap();
    assert_eq!(st1, StepExecutionStatus::Completed);

    // Step 2 halts on confirmation gate
    let st2_gate = session.advance_step(access_spec, true).unwrap();
    assert_eq!(st2_gate, StepExecutionStatus::AwaitingConfirmation);

    // Simulate cross-substrate persistence: serialize to JSON
    let wire_json = session.to_json().unwrap();

    // Rehydrate session from wire format
    let mut rehydrated: RunbookExecutionSession = RunbookExecutionSession::from_json(&wire_json).unwrap();
    assert_eq!(rehydrated.status, RunbookExecutionStatus::AwaitingConfirmation);
    assert_eq!(rehydrated.current_step_index, 1);

    // Confirm and complete rehydrated session
    assert!(rehydrated.confirm_current_step().is_ok());
    let st2_complete = rehydrated.advance_step(access_spec, true).unwrap();
    assert_eq!(st2_complete, StepExecutionStatus::Completed);
    assert_eq!(rehydrated.status, RunbookExecutionStatus::Completed);
}
