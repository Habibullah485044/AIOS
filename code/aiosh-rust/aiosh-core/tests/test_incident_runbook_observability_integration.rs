//! Integration tests for Incident Response Runbooks Observability (T-03038).

use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_observability::*;
use aiosh_core::incident_runbook_policy::*;

#[test]
fn test_integration_observability_end_to_end_lifecycle() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let policy = RunbookSecurityPolicy::default();

    // Generate snapshot with 2 active sessions
    let snapshot = RunbookObservabilityService::generate_snapshot(&baseline, &policy, 2).unwrap();

    assert_eq!(snapshot.total_catalog_runbooks, 2);
    assert_eq!(snapshot.active_sessions_count, 2);
    assert_eq!(snapshot.active_sessions_utilization_percent, 2.0);
    assert!(snapshot.is_healthy);

    // Cross-substrate canonical JSON roundtrip
    let serialized = serde_json::to_string(&snapshot).unwrap();
    let deserialized: RunbookObservabilitySnapshot = serde_json::from_str(&serialized).unwrap();

    assert_eq!(deserialized.total_catalog_runbooks, snapshot.total_catalog_runbooks);
    assert_eq!(deserialized.active_sessions_count, snapshot.active_sessions_count);
    assert_eq!(deserialized.is_healthy, snapshot.is_healthy);
    assert_eq!(deserialized.policy_mode, RunbookEnforcementMode::Enforcing);
}
