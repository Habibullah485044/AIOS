//! Scaffold tests for Incident Response Runbooks Core Service (T-02975).

use std::collections::HashMap;
use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_service::*;

#[test]
fn test_incident_runbook_service_scaffold_types() {
    assert_eq!(StepExecutionStatus::Pending.as_str(), "pending");
    assert_eq!(StepExecutionStatus::parse_status("running"), Some(StepExecutionStatus::Running));
    assert_eq!(StepExecutionStatus::parse_status("awaiting_confirmation"), Some(StepExecutionStatus::AwaitingConfirmation));

    assert_eq!(RunbookExecutionStatus::Pending.as_str(), "pending");
    assert_eq!(RunbookExecutionStatus::parse_status("completed"), Some(RunbookExecutionStatus::Completed));
    assert_eq!(RunbookExecutionStatus::parse_status("aborted"), Some(RunbookExecutionStatus::Aborted));

    let record = StepExecutionRecord::new("STEP-01", "echo containment");
    assert_eq!(record.step_id, "STEP-01");
    assert_eq!(record.status, StepExecutionStatus::Pending);
}

#[test]
fn test_incident_runbook_service_template_interpolation() {
    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "1337".to_string());
    params.insert("target_uid".to_string(), "1000".to_string());

    let template = "aiosh run kill -STOP {target_pid}";
    let rendered = render_action_template(template, &params).unwrap();
    assert_eq!(rendered, "aiosh run kill -STOP 1337");

    // Missing parameter error
    let missing_template = "aiosh isolate {missing_param}";
    assert!(render_action_template(missing_template, &params).is_err());

    // Injection attempt error
    params.insert("bad_param".to_string(), "1337; rm -rf /".to_string());
    let bad_template = "aiosh run kill {bad_param}";
    assert!(render_action_template(bad_template, &params).is_err());
}

#[test]
fn test_incident_runbook_session_scaffold_init() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware_spec = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();

    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "4242".to_string());
    params.insert("target_uid".to_string(), "1001".to_string());

    let session = RunbookExecutionSession::init_from_spec(malware_spec, "INC-2026-001", params).unwrap();
    assert_eq!(session.runbook_id, "RB-IR-MALWARE-01");
    assert_eq!(session.incident_id, "INC-2026-001");
    assert_eq!(session.status, RunbookExecutionStatus::Pending);
    assert_eq!(session.step_records.len(), 3);
    assert_eq!(session.step_records[0].command_rendered, "aiosh run kill -STOP 4242");
    assert!(!session.is_terminal());
}
