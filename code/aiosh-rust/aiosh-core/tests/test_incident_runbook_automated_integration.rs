//! End-to-End Integration Tests for Incident Response Runbooks Automated Tests (T-03018).
//!
//! Validates cross-substrate schema parity, SQLite audit ring integration,
//! and full end-to-end execution flow.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_service::*;
use aiosh_core::sec_tools::*;

#[test]
fn test_integration_cross_substrate_schema_parity() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let json_catalog = baseline.to_json().expect("Catalog serialization must succeed");

    let val: serde_json::Value = serde_json::from_str(&json_catalog).expect("Must parse as JSON");
    assert_eq!(val["version"], "1.0.0");
    assert!(val["runbooks"].is_array());
    assert_eq!(val["runbooks"].as_array().unwrap().len(), 2);

    let malware = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();
    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "5555".to_string());
    params.insert("target_uid".to_string(), "1000".to_string());

    let mut session = RunbookExecutionSession::init_from_spec(malware, "INC-INTEG-01", params).unwrap();
    session.advance_step(malware, true).unwrap();

    let json_session = session.to_json().expect("Session serialization must succeed");
    let sess_val: serde_json::Value = serde_json::from_str(&json_session).expect("Must parse session JSON");

    assert_eq!(sess_val["runbook_id"], "RB-IR-MALWARE-01");
    assert_eq!(sess_val["incident_id"], "INC-INTEG-01");
    assert_eq!(sess_val["status"], "running");
    assert_eq!(sess_val["current_step_index"], 1);
    assert_eq!(sess_val["step_records"].as_array().unwrap().len(), 3);
}

#[test]
fn test_integration_full_incident_remediation_lifecycle() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let access = baseline.get_runbook("RB-IR-ACCESS-01").unwrap();

    let mut params = HashMap::new();
    params.insert("grant_id".to_string(), "GRANT-EXP-01".to_string());
    params.insert("session_id".to_string(), "SESS-REV-99".to_string());

    let mut session = RunbookExecutionSession::init_from_spec(access, "INC-SEC-88", params).unwrap();
    assert_eq!(session.status, RunbookExecutionStatus::Pending);

    // Step 1: automated execution
    let s1 = session.advance_step(access, true).unwrap();
    assert_eq!(s1, StepExecutionStatus::Completed);
    assert_eq!(session.status, RunbookExecutionStatus::Running);

    // Step 2: requires confirmation
    let s2 = session.advance_step(access, true).unwrap();
    assert_eq!(s2, StepExecutionStatus::AwaitingConfirmation);
    assert_eq!(session.status, RunbookExecutionStatus::AwaitingConfirmation);

    // Confirmation provided with operator token
    session.confirm_with_token("security_lead", "CONFIRM-TOKEN-XYZ").unwrap();
    assert!(session.operator_confirmed);

    // Step 2 resumes and finishes
    let s2_res = session.advance_step(access, true).unwrap();
    assert_eq!(s2_res, StepExecutionStatus::Completed);
    assert_eq!(session.status, RunbookExecutionStatus::Completed);
    assert!(session.is_terminal());
}

#[test]
fn test_integration_sec_tools_end_to_end_forensics() {
    let dir = tempdir().unwrap();
    let log_path = dir.path().join("secure_audit.log");
    {
        let mut f = File::create(&log_path).unwrap();
        writeln!(f, "2026-10-15T12:00:00Z auth: pam_unix authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.100").unwrap();
        writeln!(f, "2026-10-15T12:00:01Z kernel: [12345.67] aios-pep: policy decision DENY for actor_id=untrusted").unwrap();
        f.flush().unwrap();
    }

    let search_res = scan_files(dir.path().to_str().unwrap(), "authentication failure", 10, 1024 * 1024, None).unwrap();
    assert_eq!(search_res.matches.len(), 1);
    assert!(search_res.matches[0].line_content.contains("rhost=192.168.1.100"));

    let net_res = scan_net("127.0.0.1", &[65530], 1, None).unwrap();
    assert_eq!(net_res.scanned_ports_count, 1);
}
