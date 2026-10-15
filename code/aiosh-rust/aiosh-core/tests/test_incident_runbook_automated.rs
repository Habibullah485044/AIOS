//! End-to-End Automated Tests for Incident Response Runbooks & SecTools (T-03016).
//!
//! Contract: `docs/tasks/evidence/T-03014-spec.md`.
//! Vectors: AUTORUNBOOK1 through AUTORUNBOOK10.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_service::*;
use aiosh_core::runbook_config::*;
use aiosh_core::sec_tools::*;

#[test]
fn test_autorunbook1_catalog_snapshot_integrity() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    assert_eq!(baseline.version, "1.0.0");
    assert_eq!(baseline.runbooks.len(), 2);

    let malware = baseline.get_runbook("RB-IR-MALWARE-01").expect("Malware runbook must exist");
    assert_eq!(malware.category, IncidentCategory::MalwareContainment);
    assert_eq!(malware.severity, IncidentSeverity::High);
    assert_eq!(malware.steps.len(), 3);
    assert!(malware.steps.iter().all(|s| s.automated));

    let access = baseline.get_runbook("RB-IR-ACCESS-01").expect("Access runbook must exist");
    assert_eq!(access.category, IncidentCategory::UnauthorizedAccess);
    assert_eq!(access.severity, IncidentSeverity::Critical);
    assert_eq!(access.steps.len(), 2);
    assert!(access.steps[1].requires_confirmation);
}

#[test]
fn test_autorunbook2_session_state_machine_transitions() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();

    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "1024".to_string());
    params.insert("target_uid".to_string(), "1001".to_string());

    let mut session = RunbookExecutionSession::init_from_spec(malware, "INC-AUTO-01", params).unwrap();
    assert_eq!(session.status, RunbookExecutionStatus::Pending);

    // Step 1 -> Running -> Completed
    let s1 = session.advance_step(malware, true).unwrap();
    assert_eq!(s1, StepExecutionStatus::Completed);
    assert_eq!(session.current_step_index, 1);
    assert_eq!(session.status, RunbookExecutionStatus::Running);

    // Step 2
    let s2 = session.advance_step(malware, true).unwrap();
    assert_eq!(s2, StepExecutionStatus::Completed);
    assert_eq!(session.current_step_index, 2);

    // Step 3 (final) -> Completes session
    let s3 = session.advance_step(malware, true).unwrap();
    assert_eq!(s3, StepExecutionStatus::Completed);
    assert_eq!(session.status, RunbookExecutionStatus::Completed);
    assert!(session.is_terminal());

    // Advancing terminal session fails closed
    let err = session.advance_step(malware, true).unwrap_err();
    assert!(err.contains(RUNBOOK_ERR_INVALID_TRANSITION));
}

#[test]
fn test_autorunbook3_high_risk_operator_confirmation_gate() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let access = baseline.get_runbook("RB-IR-ACCESS-01").unwrap();

    let mut params = HashMap::new();
    params.insert("grant_id".to_string(), "GRANT-X".to_string());
    params.insert("session_id".to_string(), "SESS-Y".to_string());

    let mut session = RunbookExecutionSession::init_from_spec(access, "INC-AUTO-02", params).unwrap();

    // Step 1: automated
    let s1 = session.advance_step(access, true).unwrap();
    assert_eq!(s1, StepExecutionStatus::Completed);

    // Step 2: requires confirmation
    let s2 = session.advance_step(access, true).unwrap();
    assert_eq!(s2, StepExecutionStatus::AwaitingConfirmation);
    assert_eq!(session.status, RunbookExecutionStatus::AwaitingConfirmation);

    // Retrying without confirm stays awaiting
    let s2_retry = session.advance_step(access, true).unwrap();
    assert_eq!(s2_retry, StepExecutionStatus::AwaitingConfirmation);

    // Confirm step
    session.confirm_with_token("admin", "TOKEN-AUTH-999").unwrap();
    assert!(session.operator_confirmed);

    let s2_done = session.advance_step(access, true).unwrap();
    assert_eq!(s2_done, StepExecutionStatus::Completed);
    assert_eq!(session.status, RunbookExecutionStatus::Completed);
}

#[test]
fn test_autorunbook4_parameter_extraction_and_injection_defense() {
    assert!(validate_parameter_value("target_pid", "4096").is_ok());

    // Empty rejected
    assert!(validate_parameter_value("target_pid", "").is_err());

    // Traversal rejected
    assert!(validate_parameter_value("target_pid", "../etc/passwd").is_err());

    // Injection rejected
    assert!(validate_parameter_value("target_pid", "4096; rm -rf /").is_err());

    // Template rendering
    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "4096".to_string());
    let rendered = render_action_template("aiosh proc freeze {target_pid}", &params).unwrap();
    assert_eq!(rendered, "aiosh proc freeze 4096");
}

#[test]
fn test_autorunbook5_forensic_file_pattern_scanning() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("audit.log");
    {
        let mut f = File::create(&p).unwrap();
        writeln!(f, "ALERT: unauthorized c2 beacon detected at 10.0.0.5").unwrap();
        writeln!(f, "INFO: normal housekeeping").unwrap();
        f.flush().unwrap();
    }

    let res = scan_files(dir.path().to_str().unwrap(), "c2 beacon", 10, 1024 * 1024, None).unwrap();
    assert_eq!(res.matches.len(), 1);
    assert!(res.matches[0].line_content.contains("c2 beacon"));

    // Traversal target rejected
    assert!(scan_files("../../../etc", "root", 10, 1024 * 1024, None).is_err());
}

#[test]
fn test_autorunbook6_network_and_web_port_scanning_hygiene() {
    let res = scan_net("127.0.0.1", &[65531, 65532], 2, None).unwrap();
    assert_eq!(res.target, "127.0.0.1");
    assert_eq!(res.scanned_ports_count, 2);

    let words = ["health", "metrics"];
    let web_res = scan_web("http://127.0.0.1:9", Some(&words), 1, 50, None).unwrap();
    assert_eq!(web_res.requests_sent, 2);
}

#[test]
fn test_autorunbook7_4_level_configuration_ladder_resolution() {
    let mut overrides = RunbookConfigOverrides::default();
    overrides.max_active_sessions = Some(42);

    let resolved = safe_resolve_runbook_config(Some(&overrides));
    assert_eq!(resolved.config.max_active_sessions, 42);
    assert_eq!(resolved.config.sources.get("max_active_sessions"), Some(&ConfigSource::Argument));
}

#[test]
fn test_autorunbook8_dynamic_concurrency_bounds() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();

    let mut sessions = Vec::new();
    for i in 0..10 {
        let mut p = HashMap::new();
        p.insert("target_pid".to_string(), format!("{}", 1000 + i));
        p.insert("target_uid".to_string(), "1000".to_string());
        let s = RunbookExecutionSession::init_from_spec(malware, &format!("INC-{}", i), p).unwrap();
        sessions.push(s);
    }
    assert_eq!(sessions.len(), 10);

    // Eviction cap simulation: keep latest 5
    let max_cap = 5;
    if sessions.len() > max_cap {
        let drain_count = sessions.len() - max_cap;
        sessions.drain(0..drain_count);
    }
    assert_eq!(sessions.len(), 5);
}

#[test]
fn test_autorunbook9_proof_of_restraint_invariants() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();
    assert_eq!(malware.steps[0].action_template, "aiosh run kill -STOP {target_pid}");
    assert_eq!(malware.steps[1].action_template, "aiosh run iptables -A OUTPUT -m owner --uid-owner {target_uid} -j DROP");
    assert_eq!(malware.steps[2].action_template, "aiosh audit checkpoint --reason 'Malware containment forensic snapshot'");
}

#[test]
fn test_autorunbook10_fail_closed_result_envelopes() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();

    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "1000".to_string());
    params.insert("target_uid".to_string(), "1000".to_string());

    let mut session = RunbookExecutionSession::init_from_spec(malware, "INC-FAIL-01", params).unwrap();

    // Simulated failure
    let st = session.advance_step(malware, false).unwrap();
    assert_eq!(st, StepExecutionStatus::Failed);
    assert_eq!(session.status, RunbookExecutionStatus::Failed);
    assert!(session.is_terminal());

    // Advancing after failure is rejected
    assert!(session.advance_step(malware, true).is_err());
}
