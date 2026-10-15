//! Integration & Hardening tests for Incident Response Runbooks Security Policy (T-03030).
//!
//! Tests error envelopes, boundary clamping, temp file cleanup, and fail-open audit rows.

use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_policy::*;
use std::fs;

#[test]
fn test_hardening_bounds_validation_on_extremes() {
    let mut policy = RunbookSecurityPolicy::default();
    policy.max_step_timeout_seconds = 500; // exceeds MAX_PERMISSIBLE_STEP_TIMEOUT_SECS (300)
    assert!(policy.validate_bounds().is_err());

    let mut policy2 = RunbookSecurityPolicy::default();
    policy2.max_scanned_ports = 70_000; // exceeds 65535
    assert!(policy2.validate_bounds().is_err());

    let mut policy3 = RunbookSecurityPolicy::default();
    policy3.max_file_scan_depth = 50; // exceeds 32
    assert!(policy3.validate_bounds().is_err());
}

#[test]
fn test_hardening_result_envelope_failure_modes() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let access = baseline.get_runbook("RB-IR-ACCESS-01").unwrap();
    let step2 = &access.steps[1]; // high-risk step requiring confirmation

    let policy = RunbookSecurityPolicy::default();

    // Unconfirmed high risk step
    let res = policy.evaluate_step_with_envelope(step2, false);
    assert!(!res.ok);
    assert_eq!(res.error_code, Some(RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED.to_string()));
    assert!(res.audit_row_required);

    // Confirmed high risk step
    let res_confirmed = policy.evaluate_step_with_envelope(step2, true);
    assert!(res_confirmed.ok);
    assert!(!res_confirmed.audit_row_required);
}

#[test]
fn test_hardening_permissive_fail_open_writes_honest_audit() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let access = baseline.get_runbook("RB-IR-ACCESS-01").unwrap();
    let step2 = &access.steps[1];

    let mut policy = RunbookSecurityPolicy::default();
    policy.mode = RunbookEnforcementMode::Permissive;

    // Under Permissive mode, execution proceeds (ok = true) but honest audit row is strictly REQUIRED
    let res = policy.evaluate_step_with_envelope(step2, false);
    assert!(res.ok);
    assert!(res.audit_row_required, "ADR-0035 AF-2 requires honest audit on permissive bypass");
}

#[test]
fn test_hardening_atomic_save_and_cleanup_no_temp_leak() {
    let policy = RunbookSecurityPolicy::default();
    let temp_dir = std::env::temp_dir();
    let target_file = temp_dir.join("test_runbook_policy_hardening.json");
    let target_path = target_file.to_str().unwrap();

    let save_res = policy.save_to_file(target_path);
    assert!(save_res.is_ok());
    assert!(target_file.exists());

    let loaded = RunbookSecurityPolicy::load_from_file(target_path).unwrap();
    assert_eq!(loaded.max_step_timeout_seconds, policy.max_step_timeout_seconds);

    // Verify no leftover .tmp files
    let tmp_pattern = format!("{}.tmp.{}", target_path, std::process::id());
    assert!(!std::path::Path::new(&tmp_pattern).exists(), "Temp file must be cleaned up");

    // Clean up
    let _ = fs::remove_file(target_file);
}
