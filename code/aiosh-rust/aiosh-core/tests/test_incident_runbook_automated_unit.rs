//! Focused Unit Tests for Incident Response Runbooks Automated Test vectors (T-03017).
//!
//! Validates boundaries, negative cases, invalid inputs, and primary failure modes.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_service::*;
use aiosh_core::sec_tools::*;

#[test]
fn test_unit_boundary_parameter_bounds() {
    // Exact max parameter length (256)
    let max_val = "a".repeat(256);
    assert!(validate_parameter_value("param", &max_val).is_ok());

    // Exceeding max parameter length (257) fails
    let over_val = "a".repeat(257);
    let err = validate_parameter_value("param", &over_val).unwrap_err();
    assert!(err.contains(RUNBOOK_ERR_BOUNDS_EXCEEDED));

    // Empty parameter value fails
    let err_empty = validate_parameter_value("param", "").unwrap_err();
    assert!(err_empty.contains(RUNBOOK_ERR_INVALID_PARAM_VALUE));
}

#[test]
fn test_unit_boundary_parameters_count() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();

    let mut params = HashMap::new();
    for i in 0..33 {
        params.insert(format!("param_{}", i), "value".to_string());
    }
    // Exceeding 32 parameters fails
    let err = RunbookExecutionSession::init_from_spec(malware, "INC-OVERFLOW", params).unwrap_err();
    assert!(err.contains(RUNBOOK_ERR_BOUNDS_EXCEEDED));
}

#[test]
fn test_unit_invalid_inputs_in_runbook_steps() {
    // Reject steps with empty IDs
    let err_id = RunbookStep::new(
        "",
        "Valid description",
        RunbookPhase::Containment,
        RunbookTargetSubstrate::Process,
        "aiosh kill {pid}",
        true,
        false,
        15,
    );
    assert!(err_id.is_err());

    // Reject steps with control characters in description
    let err_ctrl = RunbookStep::new(
        "STEP-01",
        "Bad\x00Description",
        RunbookPhase::Containment,
        RunbookTargetSubstrate::Process,
        "aiosh kill {pid}",
        true,
        false,
        15,
    );
    assert!(err_ctrl.is_err());

    // Reject steps with invalid action templates (e.g. unclosed brace)
    let err_tpl = RunbookStep::new(
        "STEP-01",
        "Valid description",
        RunbookPhase::Containment,
        RunbookTargetSubstrate::Process,
        "aiosh kill {pid",
        true,
        false,
        15,
    );
    assert!(err_tpl.is_err());
}

#[test]
fn test_unit_primary_failure_mode_simulation() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();

    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "9000".to_string());
    params.insert("target_uid".to_string(), "1000".to_string());

    let mut session = RunbookExecutionSession::init_from_spec(malware, "INC-FAIL-TEST", params).unwrap();

    // Primary failure mode: step fails during execution
    let st = session.advance_step(malware, false).unwrap();
    assert_eq!(st, StepExecutionStatus::Failed);
    assert_eq!(session.status, RunbookExecutionStatus::Failed);

    let rec = &session.step_records[0];
    assert_eq!(rec.status, StepExecutionStatus::Failed);
    assert_eq!(rec.exit_code, Some(1));
    assert!(rec.error_message.as_ref().unwrap().contains("failure"));

    // Ensure session cannot advance further once failed
    let next_attempt = session.advance_step(malware, true);
    assert!(next_attempt.is_err());
}

#[test]
fn test_unit_abort_transition_lifecycle() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();

    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "9001".to_string());
    params.insert("target_uid".to_string(), "1000".to_string());

    let mut session = RunbookExecutionSession::init_from_spec(malware, "INC-ABORT-TEST", params).unwrap();

    // Abort session while pending
    session.abort("Operator cancelled incident response").unwrap();
    assert_eq!(session.status, RunbookExecutionStatus::Aborted);
    assert!(session.is_terminal());

    // Cannot abort twice
    assert!(session.abort("Second abort").is_err());

    // Cannot advance aborted session
    assert!(session.advance_step(malware, true).is_err());
}

#[test]
fn test_unit_sec_tools_target_validation_negative_cases() {
    // Negative test: Shell metacharacters injection
    assert!(validate_scan_target("target.com; rm -rf /").is_err());
    assert!(validate_scan_target("target.com && cat /etc/shadow").is_err());
    assert!(validate_scan_target("`uname -a`").is_err());
    assert!(validate_scan_target("$(id)").is_err());

    // Negative test: Path traversal in target
    assert!(validate_scan_target("../secret/file").is_err());
    assert!(validate_scan_target("/var/log/../../etc/passwd").is_err());

    // Negative test: Control characters in target
    assert!(validate_scan_target("target\x00.com").is_err());
    assert!(validate_scan_target("target\n.com").is_err());
}

#[test]
fn test_unit_sec_tools_file_scan_bounds() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("test.txt");
    {
        let mut f = File::create(&p).unwrap();
        writeln!(f, "safe content").unwrap();
        f.flush().unwrap();
    }

    // Pattern empty
    assert!(scan_files(dir.path().to_str().unwrap(), "", 5, 1024, None).is_err());

    // Non-existent directory
    assert!(scan_files("C:/non/existent/path/for/testing/aios", "test", 5, 1024, None).is_err());
}
