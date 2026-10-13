//! Unit tests for Incident Response Runbooks Core Service (T-02977).

use std::collections::HashMap;
use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_service::*;

#[test]
fn test_session_lifecycle_normal_progression() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware_spec = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();

    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "9999".to_string());
    params.insert("target_uid".to_string(), "1002".to_string());

    let mut session = RunbookExecutionSession::init_from_spec(malware_spec, "INC-NORM-01", params).unwrap();
    assert_eq!(session.status, RunbookExecutionStatus::Pending);
    assert_eq!(session.current_step_index, 0);

    // Step 1: Automated
    let st1 = session.advance_step(malware_spec, true).unwrap();
    assert_eq!(st1, StepExecutionStatus::Completed);
    assert_eq!(session.current_step_index, 1);
    assert_eq!(session.status, RunbookExecutionStatus::Running);

    // Step 2: Automated
    let st2 = session.advance_step(malware_spec, true).unwrap();
    assert_eq!(st2, StepExecutionStatus::Completed);
    assert_eq!(session.current_step_index, 2);

    // Step 3: Automated
    let st3 = session.advance_step(malware_spec, true).unwrap();
    assert_eq!(st3, StepExecutionStatus::Completed);
    assert_eq!(session.current_step_index, 3);
    assert_eq!(session.status, RunbookExecutionStatus::Completed);
    assert!(!session.completed_at.is_empty());
    assert!(session.is_terminal());

    // Advancing terminal session fails
    assert!(session.advance_step(malware_spec, true).is_err());
}

#[test]
fn test_session_confirmation_gate_enforcement() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let access_spec = baseline.get_runbook("RB-IR-ACCESS-01").unwrap();

    let mut params = HashMap::new();
    params.insert("grant_id".to_string(), "GRANT-123".to_string());
    params.insert("session_id".to_string(), "SESS-456".to_string());

    let mut session = RunbookExecutionSession::init_from_spec(access_spec, "INC-CONF-01", params).unwrap();

    // Step 1: Automated revocation
    let st1 = session.advance_step(access_spec, true).unwrap();
    assert_eq!(st1, StepExecutionStatus::Completed);
    assert_eq!(session.current_step_index, 1);

    // Step 2: Requires confirmation!
    let st2_attempt1 = session.advance_step(access_spec, true).unwrap();
    assert_eq!(st2_attempt1, StepExecutionStatus::AwaitingConfirmation);
    assert_eq!(session.status, RunbookExecutionStatus::AwaitingConfirmation);
    assert_eq!(session.current_step_index, 1); // Does not advance

    // Attempting to advance again without confirmation remains awaiting
    let st2_attempt2 = session.advance_step(access_spec, true).unwrap();
    assert_eq!(st2_attempt2, StepExecutionStatus::AwaitingConfirmation);

    // Provide confirmation
    assert!(session.confirm_current_step().is_ok());
    assert_eq!(session.status, RunbookExecutionStatus::Running);

    // Now execute Step 2
    let st2_executed = session.advance_step(access_spec, true).unwrap();
    assert_eq!(st2_executed, StepExecutionStatus::Completed);
    assert_eq!(session.status, RunbookExecutionStatus::Completed);
}

#[test]
fn test_session_abort_handling() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware_spec = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();

    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "100".to_string());
    params.insert("target_uid".to_string(), "1000".to_string());

    let mut session = RunbookExecutionSession::init_from_spec(malware_spec, "INC-ABORT-01", params).unwrap();

    assert!(session.abort("Operator requested immediate stop").is_ok());
    assert_eq!(session.status, RunbookExecutionStatus::Aborted);
    assert_eq!(session.step_records[0].status, StepExecutionStatus::Skipped);
    assert!(session.is_terminal());

    // Further operations rejected
    assert!(session.advance_step(malware_spec, true).is_err());
}

#[test]
fn test_session_failure_and_timeout_handling() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware_spec = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();

    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "100".to_string());
    params.insert("target_uid".to_string(), "1000".to_string());

    let mut session_fail = RunbookExecutionSession::init_from_spec(malware_spec, "INC-FAIL-01", params.clone()).unwrap();
    let st_fail = session_fail.advance_step(malware_spec, false).unwrap();
    assert_eq!(st_fail, StepExecutionStatus::Failed);
    assert_eq!(session_fail.status, RunbookExecutionStatus::Failed);
    assert!(session_fail.is_terminal());

    let mut session_timeout = RunbookExecutionSession::init_from_spec(malware_spec, "INC-TO-01", params).unwrap();
    assert!(session_timeout.timeout_current().is_ok());
    assert_eq!(session_timeout.status, RunbookExecutionStatus::Failed);
    assert_eq!(session_timeout.step_records[0].status, StepExecutionStatus::TimedOut);
    assert_eq!(session_timeout.step_records[0].exit_code, Some(124));
}

#[test]
fn test_catalog_matching_and_json_roundtrip() {
    let catalog = RunbookCatalogSnapshot::canonical_baseline();

    // Match malware high
    let matched_mw = match_runbook(&catalog, IncidentCategory::MalwareContainment, IncidentSeverity::High);
    assert!(matched_mw.is_some());
    assert_eq!(matched_mw.unwrap().id, "RB-IR-MALWARE-01");

    // Match unauthorized access critical
    let matched_ua = match_runbook(&catalog, IncidentCategory::UnauthorizedAccess, IncidentSeverity::Critical);
    assert!(matched_ua.is_some());
    assert_eq!(matched_ua.unwrap().id, "RB-IR-ACCESS-01");

    // Serialization roundtrip
    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "555".to_string());
    params.insert("target_uid".to_string(), "555".to_string());
    let session = RunbookExecutionSession::init_from_spec(matched_mw.unwrap(), "INC-JSON-01", params).unwrap();

    let json = session.to_json().unwrap();
    let rehydrated = RunbookExecutionSession::from_json(&json).unwrap();
    assert_eq!(session.session_id, rehydrated.session_id);
    assert_eq!(session.step_records.len(), rehydrated.step_records.len());
    assert_eq!(session.status, rehydrated.status);
}
