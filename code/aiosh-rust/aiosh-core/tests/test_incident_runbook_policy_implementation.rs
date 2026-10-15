//! Implementation tests for Incident Response Runbooks Security Policy (T-03026).

use tempfile::tempdir;

use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_policy::*;

#[test]
fn test_policy_implementation_evaluation_matrix() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();
    let access = baseline.get_runbook("RB-IR-ACCESS-01").unwrap();

    let mut policy = RunbookSecurityPolicy::default();

    // Default policy allows canonical runbooks
    assert!(policy.evaluate_runbook_start(malware).is_ok());
    assert!(policy.evaluate_runbook_start(access).is_ok());

    // Disallow category
    policy.disallowed_categories.push(IncidentCategory::MalwareContainment);
    let err_cat = policy.evaluate_runbook_start(malware).unwrap_err();
    assert!(err_cat.contains(RUNBOOKPOL_ERR_CATEGORY_DISALLOWED));

    // Reset and disallow substrate
    policy.disallowed_categories.clear();
    policy.disallowed_substrates.push(RunbookTargetSubstrate::Network);
    let err_sub = policy.evaluate_runbook_start(malware).unwrap_err();
    assert!(err_sub.contains(RUNBOOKPOL_ERR_SUBSTRATE_DISALLOWED));
}

#[test]
fn test_policy_implementation_step_advance_and_confirmation_gate() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let access = baseline.get_runbook("RB-IR-ACCESS-01").unwrap();
    let step2 = &access.steps[1]; // requires confirmation

    let policy = RunbookSecurityPolicy::default();

    // Advancing high-risk step without confirmation is blocked
    let err_gate = policy.evaluate_step_advance(step2, false).unwrap_err();
    assert!(err_gate.contains(RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED));

    // With confirmation it succeeds
    assert!(policy.evaluate_step_advance(step2, true).is_ok());

    // Timeout violation
    let mut bad_step = step2.clone();
    bad_step.timeout_seconds = 120; // exceeds default 60s
    let err_timeout = policy.evaluate_step_advance(&bad_step, true).unwrap_err();
    assert!(err_timeout.contains(RUNBOOKPOL_ERR_POLICY_VIOLATION));
}

#[test]
fn test_policy_implementation_file_io_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("policy.json");
    let path_str = path.to_str().unwrap();

    let mut policy = RunbookSecurityPolicy::default();
    policy.max_step_timeout_seconds = 99;
    policy.disallowed_categories.push(IncidentCategory::DenialOfService);

    // Save
    policy.save_to_file(path_str).unwrap();

    // Load
    let loaded = RunbookSecurityPolicy::load_from_file(path_str).unwrap();
    assert_eq!(loaded.max_step_timeout_seconds, 99);
    assert_eq!(loaded.disallowed_categories, vec![IncidentCategory::DenialOfService]);
}
