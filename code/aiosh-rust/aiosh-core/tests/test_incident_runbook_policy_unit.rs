//! Focused Unit Tests for Incident Response Runbooks Security Policy (T-03027).

use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_policy::*;

#[test]
fn test_unit_boundary_step_timeouts() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();
    let mut step = malware.steps[0].clone();

    let mut policy = RunbookSecurityPolicy::default();
    policy.max_step_timeout_seconds = 30;

    // Exact boundary: 30s passes
    step.timeout_seconds = 30;
    assert!(policy.evaluate_step_advance(&step, true).is_ok());

    // Exceeds boundary: 31s fails
    step.timeout_seconds = 31;
    let err = policy.evaluate_step_advance(&step, true).unwrap_err();
    assert!(err.contains(RUNBOOKPOL_ERR_POLICY_VIOLATION));
}

#[test]
fn test_unit_boundary_scan_ports_and_depth() {
    let mut policy = RunbookSecurityPolicy::default();
    policy.max_scanned_ports = 100;
    policy.max_file_scan_depth = 5;

    // Exact port bound passes
    assert!(policy.evaluate_scan_operation("net", 100, 1).is_ok());

    // Exceeding port bound fails
    let err_ports = policy.evaluate_scan_operation("net", 101, 1).unwrap_err();
    assert!(err_ports.contains(RUNBOOKPOL_ERR_SCAN_BOUNDS));

    // Exact depth bound passes
    assert!(policy.evaluate_scan_operation("files", 1, 5).is_ok());

    // Exceeding depth bound fails
    let err_depth = policy.evaluate_scan_operation("files", 1, 6).unwrap_err();
    assert!(err_depth.contains(RUNBOOKPOL_ERR_SCAN_BOUNDS));
}

#[test]
fn test_unit_disabled_enforcement_mode_bypass() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let access = baseline.get_runbook("RB-IR-ACCESS-01").unwrap();
    let step2 = &access.steps[1];

    let mut policy = RunbookSecurityPolicy::default();
    policy.mode = RunbookEnforcementMode::Disabled;
    policy.disallowed_categories.push(IncidentCategory::UnauthorizedAccess);

    // Disabled mode bypasses category check
    assert!(policy.evaluate_runbook_start(access).is_ok());

    // Disabled mode bypasses confirmation gate
    assert!(policy.evaluate_step_advance(step2, false).is_ok());

    // Disabled mode bypasses scan limits
    assert!(policy.evaluate_scan_operation("net", 999999, 999).is_ok());
}

#[test]
fn test_unit_file_io_invalid_inputs_and_bounds() {
    let dir = tempdir().unwrap();

    // Non-existent file
    assert!(RunbookSecurityPolicy::load_from_file("non_existent_policy.json").is_err());

    // Corrupted JSON
    let bad_json_path = dir.path().join("bad.json");
    {
        let mut f = File::create(&bad_json_path).unwrap();
        writeln!(f, "{{ malformed json content").unwrap();
        f.flush().unwrap();
    }
    let err_corrupt = RunbookSecurityPolicy::load_from_file(bad_json_path.to_str().unwrap()).unwrap_err();
    assert!(err_corrupt.contains(RUNBOOKPOL_ERR_VALIDATION));

    // Oversized policy file (> 64 KiB)
    let big_path = dir.path().join("big.json");
    {
        let mut f = File::create(&big_path).unwrap();
        let zeros = vec![b' '; (MAX_RUNBOOK_POLICY_BYTES + 1) as usize];
        f.write_all(&zeros).unwrap();
        f.flush().unwrap();
    }
    let err_big = RunbookSecurityPolicy::load_from_file(big_path.to_str().unwrap()).unwrap_err();
    assert!(err_big.contains(RUNBOOKPOL_ERR_IO));
}
