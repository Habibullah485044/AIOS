//! Scaffold test for Incident Response Runbooks Security Policy (T-03025).

use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_policy::*;

#[test]
fn test_policy_scaffold_default_initialization() {
    let policy = RunbookSecurityPolicy::default();
    assert_eq!(policy.version, "1.0.0");
    assert_eq!(policy.mode, RunbookEnforcementMode::Enforcing);
    assert!(policy.require_operator_confirmation_for_high_risk);
    assert_eq!(policy.max_step_timeout_seconds, DEFAULT_MAX_STEP_TIMEOUT_SECS);
    assert_eq!(policy.max_active_sessions, 100);
    assert_eq!(policy.max_scanned_ports, DEFAULT_MAX_SCANNED_PORTS);
    assert_eq!(policy.max_file_scan_depth, DEFAULT_MAX_FILE_SCAN_DEPTH);
    assert!(policy.require_pep_grant);

    // Error codes defined
    assert_eq!(RUNBOOKPOL_ERR_VALIDATION, "RUNBOOKPOL_ERR_VALIDATION");
    assert_eq!(RUNBOOKPOL_ERR_POLICY_VIOLATION, "RUNBOOKPOL_ERR_POLICY_VIOLATION");
    assert_eq!(RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED, "RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED");
}

#[test]
fn test_policy_scaffold_fail_loudly() {
    let policy = RunbookSecurityPolicy::default();
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();
    assert!(policy.evaluate_runbook_start(malware).is_ok());
}

