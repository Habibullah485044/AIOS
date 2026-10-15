//! Implementation tests for Incident Response Runbooks Observability (T-03036).

use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_observability::*;
use aiosh_core::incident_runbook_policy::*;

#[test]
fn test_observability_implementation_metrics_calculation() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let policy = RunbookSecurityPolicy::default();

    let snapshot = RunbookObservabilityService::generate_snapshot(&baseline, &policy, 5).unwrap();

    assert_eq!(snapshot.total_catalog_runbooks, 2);
    assert_eq!(snapshot.total_executions, 7); // 2 catalog runbooks + 5 active
    assert_eq!(snapshot.active_sessions_count, 5);
    assert_eq!(snapshot.active_sessions_utilization_percent, 5.0);
    assert!(snapshot.is_healthy);

    // Verify executions by category
    assert_eq!(snapshot.executions_by_category.get(&IncidentCategory::MalwareContainment), Some(&1));
    assert_eq!(snapshot.executions_by_category.get(&IncidentCategory::UnauthorizedAccess), Some(&1));

    // Verify step executions by phase
    assert!(snapshot.step_executions_by_phase.contains_key(&RunbookPhase::Containment));
    assert!(snapshot.step_executions_by_phase.contains_key(&RunbookPhase::PostIncident));



}

#[test]
fn test_observability_implementation_validation_bounds() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let policy = RunbookSecurityPolicy::default();

    let mut snapshot = RunbookObservabilityService::generate_snapshot(&baseline, &policy, 0).unwrap();

    // Valid snapshot passes
    assert!(RunbookObservabilityService::validate_snapshot(&snapshot).is_ok());

    // Out-of-bounds utilization
    snapshot.active_sessions_utilization_percent = 150.0;
    assert!(RunbookObservabilityService::validate_snapshot(&snapshot).is_err());

    // Empty timestamp
    snapshot.active_sessions_utilization_percent = 0.0;
    snapshot.generated_at_utc = "".to_string();
    assert!(RunbookObservabilityService::validate_snapshot(&snapshot).is_err());
}
