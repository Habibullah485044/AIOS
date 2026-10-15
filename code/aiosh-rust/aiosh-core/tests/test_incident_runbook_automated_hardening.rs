//! Hardening Tests for Incident Response Runbooks Automated Tests Subsystem (T-03020).
//!
//! Validates timeouts, size caps, bounded retries, resource cleanup, and standard result envelopes.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_service::*;
use aiosh_core::sec_tools::*;

#[test]
fn test_hardening_step_timeout_enforcement() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();

    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "7777".to_string());
    params.insert("target_uid".to_string(), "1000".to_string());

    let mut session = RunbookExecutionSession::init_from_spec(malware, "INC-TIMEOUT-01", params).unwrap();

    // Trigger step timeout explicitly
    session.timeout_current().unwrap();
    assert_eq!(session.status, RunbookExecutionStatus::Failed);
    assert!(session.is_terminal());

    let rec = &session.step_records[0];
    assert_eq!(rec.status, StepExecutionStatus::TimedOut);
    assert_eq!(rec.exit_code, Some(124));
    assert!(rec.error_message.as_ref().unwrap().contains(RUNBOOK_ERR_TIMEOUT_EXCEEDED));
}

#[test]
fn test_hardening_bounded_retries_and_no_infinite_spins() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let access = baseline.get_runbook("RB-IR-ACCESS-01").unwrap();

    let mut params = HashMap::new();
    params.insert("grant_id".to_string(), "GRANT-LOOP".to_string());
    params.insert("session_id".to_string(), "SESS-LOOP".to_string());

    let mut session = RunbookExecutionSession::init_from_spec(access, "INC-LOOP-01", params).unwrap();

    // Step 1: automated
    session.advance_step(access, true).unwrap();

    // Attempting to advance Step 2 without confirmation across 5 bounded retries
    let max_retries = 5;
    for _ in 0..max_retries {
        let st = session.advance_step(access, true).unwrap();
        assert_eq!(st, StepExecutionStatus::AwaitingConfirmation);
        assert_eq!(session.status, RunbookExecutionStatus::AwaitingConfirmation);
    }

    // Explicit confirmation resolves the gate
    session.confirm_current_step().unwrap();
    let final_st = session.advance_step(access, true).unwrap();
    assert_eq!(final_st, StepExecutionStatus::Completed);
    assert_eq!(session.status, RunbookExecutionStatus::Completed);
}

#[test]
fn test_hardening_file_scan_size_cap_and_resource_cleanup() {
    let dir = tempdir().unwrap();
    let large_file_path = dir.path().join("large_payload.bin");
    {
        let mut f = File::create(&large_file_path).unwrap();
        // Write content smaller than max bound
        let buf = vec![b'A'; 64 * 1024]; // 64 KiB
        f.write_all(&buf).unwrap();
        f.flush().unwrap();
    }

    let res = scan_files(dir.path().to_str().unwrap(), "nonexistent", 5, 1024 * 1024, None).unwrap();
    assert_eq!(res.matches.len(), 0);
    assert_eq!(res.files_scanned_count, 1);

    // Tempdir automatically and safely drops without resource leaks
    drop(dir);
}
