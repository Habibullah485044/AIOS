//! Integration Tests for Incident Response Runbooks Security Policy (T-03028).

use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_policy::*;

#[test]
fn test_integration_policy_governance_on_canonical_baseline() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let malware = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();
    let access = baseline.get_runbook("RB-IR-ACCESS-01").unwrap();

    let mut policy = RunbookSecurityPolicy::default();

    // 1. Initial baseline passes
    assert!(policy.evaluate_runbook_start(malware).is_ok());
    assert!(policy.evaluate_runbook_start(access).is_ok());

    // 2. Policy-driven category exclusion
    policy.disallowed_categories.push(IncidentCategory::UnauthorizedAccess);
    let err_cat = policy.evaluate_runbook_start(access).unwrap_err();
    assert!(err_cat.contains(RUNBOOKPOL_ERR_CATEGORY_DISALLOWED));

    // 3. High-risk confirmation gate enforcement
    let high_risk_step = &access.steps[1];
    let err_conf = policy.evaluate_step_advance(high_risk_step, false).unwrap_err();
    assert!(err_conf.contains(RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED));

    // Operator confirmed succeeds
    assert!(policy.evaluate_step_advance(high_risk_step, true).is_ok());

    // 4. Port scan budget enforcement
    let err_scan = policy.evaluate_scan_operation("net", policy.max_scanned_ports + 1, 1).unwrap_err();
    assert!(err_scan.contains(RUNBOOKPOL_ERR_SCAN_BOUNDS));
}
