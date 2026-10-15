//! Scaffold tests for Incident Response Runbooks Automated Tests (T-03015).
//!
//! Contract: `docs/tasks/evidence/T-03014-spec.md`.

use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_service::*;
use aiosh_core::runbook_config::*;
use aiosh_core::sec_tools::MAX_SCAN_PORTS_COUNT;

#[test]
fn test_scaffold_imports_and_types_exist() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    assert!(!baseline.runbooks.is_empty());

    let cfg = RunbookConfig::default();
    assert_eq!(cfg.max_active_sessions, DEFAULT_MAX_ACTIVE_SESSIONS);
    assert_eq!(MAX_SCAN_PORTS_COUNT, 65535);

    // Verify error codes are defined
    assert_eq!(RUNBOOK_ERR_SESSION_NOT_FOUND, "RUNBOOK_ERR_SESSION_NOT_FOUND");
    assert_eq!(RUNBOOK_ERR_INVALID_TRANSITION, "RUNBOOK_ERR_INVALID_TRANSITION");
    assert_eq!(RUNBOOKCONF_ERR_PATH_TRAVERSAL, "RUNBOOKCONF_ERR_PATH_TRAVERSAL");
}

fn stub_autorunbook_vector(vector_id: &str) {
    unimplemented!("Vector {} scaffold - pending T-03016 implementation", vector_id);
}

#[test]
#[should_panic(expected = "pending T-03016 implementation")]
fn test_scaffold_autorunbook_fail_loudly() {
    stub_autorunbook_vector("AUTORUNBOOK1");
}
