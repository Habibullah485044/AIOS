//! Scaffold tests for Incident Response Runbooks Observability (T-03035).

use aiosh_core::incident_runbook_observability::*;
use aiosh_core::incident_runbook_policy::RunbookEnforcementMode;
use std::collections::HashMap;

#[test]
fn test_observability_scaffold_constants_and_types() {
    assert_eq!(MAX_OBSERVABILITY_PAYLOAD_BYTES, 64 * 1024);
    assert_eq!(MAX_OBSERVABILITY_ENTRIES, 128);
    assert_eq!(MAX_OBSERVABILITY_TEXT_LEN, 256);
    assert_eq!(IROBS_ERR_VALIDATION, "IROBS_ERR_VALIDATION");
    assert_eq!(IROBS_ERR_INACCESSIBLE, "IROBS_ERR_INACCESSIBLE");

    let snapshot = RunbookObservabilitySnapshot {
        generated_at_utc: "2026-10-15T14:00:00Z".to_string(),
        total_catalog_runbooks: 4,
        total_executions: 10,
        executions_by_category: HashMap::new(),
        executions_by_status: HashMap::new(),
        step_executions_by_phase: HashMap::new(),
        total_ports_scanned: 1000,
        total_files_scanned: 50,
        total_web_paths_scanned: 20,
        policy_mode: RunbookEnforcementMode::Enforcing,
        high_risk_confirmations_total: 5,
        policy_rejections_total: 0,
        active_sessions_count: 1,
        active_sessions_utilization_percent: 1.0,
        is_healthy: true,
        recent_audit_events_count: 10,
    };

    assert!(snapshot.is_healthy);
    assert_eq!(snapshot.total_catalog_runbooks, 4);
}

#[test]
#[should_panic(expected = "pending T-03036")]
fn test_observability_scaffold_fails_loudly() {
    let _ = RunbookObservabilityService::generate_snapshot();
}
