//! Focused Unit Tests for Incident Response Runbooks Observability (T-03037).
//!
//! Covers: valid input, invalid input, boundary values, and primary failure modes.

use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_observability::*;
use aiosh_core::incident_runbook_policy::*;

#[test]
fn test_unit_observability_valid_baseline_and_custom_sessions() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let policy = RunbookSecurityPolicy::default();

    // Zero active sessions
    let snap_zero = RunbookObservabilityService::generate_snapshot(&baseline, &policy, 0).unwrap();
    assert_eq!(snap_zero.active_sessions_count, 0);
    assert_eq!(snap_zero.active_sessions_utilization_percent, 0.0);
    assert_eq!(snap_zero.total_executions, 2);
    assert!(snap_zero.is_healthy);

    // Fifty active sessions
    let snap_50 = RunbookObservabilityService::generate_snapshot(&baseline, &policy, 50).unwrap();
    assert_eq!(snap_50.active_sessions_count, 50);
    assert_eq!(snap_50.active_sessions_utilization_percent, 50.0);
    assert!(snap_50.is_healthy);
}

#[test]
fn test_unit_observability_boundary_utilization_and_health() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let mut policy = RunbookSecurityPolicy::default();
    policy.max_active_sessions = 100;

    // Exact capacity boundary: 100 sessions = 100.0% utilization, still healthy
    let snap_exact = RunbookObservabilityService::generate_snapshot(&baseline, &policy, 100).unwrap();
    assert_eq!(snap_exact.active_sessions_utilization_percent, 100.0);
    assert!(snap_exact.is_healthy);

    // Over-capacity boundary: 101 sessions -> unhealthy
    let snap_over = RunbookObservabilityService::generate_snapshot(&baseline, &policy, 101).unwrap();
    assert!(!snap_over.is_healthy, "Over-capacity state must flag unhealthy");
}

#[test]
fn test_unit_observability_invalid_inputs_and_bounds() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let policy = RunbookSecurityPolicy::default();
    let mut snapshot = RunbookObservabilityService::generate_snapshot(&baseline, &policy, 0).unwrap();

    // Invalid: negative utilization
    snapshot.active_sessions_utilization_percent = -1.0;
    let err_neg = RunbookObservabilityService::validate_snapshot(&snapshot).unwrap_err();
    assert!(err_neg.contains(IROBS_ERR_VALIDATION));

    // Invalid: extreme utilization > 10000.0
    snapshot.active_sessions_utilization_percent = 15_000.0;
    let err_over = RunbookObservabilityService::validate_snapshot(&snapshot).unwrap_err();
    assert!(err_over.contains(IROBS_ERR_VALIDATION));


    // Reset utilization to valid
    snapshot.active_sessions_utilization_percent = 0.0;

    // Invalid: oversized timestamp
    snapshot.generated_at_utc = "X".repeat(MAX_OBSERVABILITY_TEXT_LEN + 1);
    let err_time = RunbookObservabilityService::validate_snapshot(&snapshot).unwrap_err();
    assert!(err_time.contains(IROBS_ERR_VALIDATION));
}

#[test]
fn test_unit_observability_primary_failure_mode_oversized_payload() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let policy = RunbookSecurityPolicy::default();
    let mut snapshot = RunbookObservabilityService::generate_snapshot(&baseline, &policy, 0).unwrap();

    // Inject huge number of dummy status keys to exceed MAX_OBSERVABILITY_PAYLOAD_BYTES
    for i in 0..2000 {
        snapshot.executions_by_status.insert(format!("status-{}", i), i);
    }

    let err_size = RunbookObservabilityService::validate_snapshot(&snapshot).unwrap_err();
    assert!(err_size.contains(IROBS_ERR_VALIDATION));
}
