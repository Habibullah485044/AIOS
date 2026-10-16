use aiosh_core::incident_runbook_data_model::RunbookCatalogSnapshot;
use aiosh_core::incident_runbook_observability::{
    RunbookObservabilityService, IROBS_ERR_VALIDATION, MAX_OBSERVABILITY_ACTIVE_SESSIONS,
};
use aiosh_core::incident_runbook_policy::RunbookSecurityPolicy;
use std::collections::HashMap;

#[test]
fn test_hardening_observability_result_envelope_success_and_failure() {
    let catalog = RunbookCatalogSnapshot::canonical_baseline();
    let policy = RunbookSecurityPolicy::default();

    // 1. Success case
    let env_ok = RunbookObservabilityService::generate_snapshot_safe(&catalog, &policy, 5);
    assert!(env_ok.ok);
    assert!(env_ok.snapshot.is_some());
    assert!(env_ok.error_code.is_none());
    assert!(!env_ok.audit_row_required);

    let snapshot = env_ok.snapshot.unwrap();
    assert_eq!(snapshot.active_sessions_count, 5);
    assert!(snapshot.is_healthy);

    // 2. Failure case with excessive sessions exceeding sanity cap
    let env_err = RunbookObservabilityService::generate_snapshot_safe(
        &catalog,
        &policy,
        MAX_OBSERVABILITY_ACTIVE_SESSIONS + 1,
    );
    assert!(!env_err.ok);
    assert!(env_err.snapshot.is_none());
    assert_eq!(env_err.error_code, Some(IROBS_ERR_VALIDATION.to_string()));
    assert!(env_err.audit_row_required);
    assert!(env_err.error_message.unwrap().contains("exceeds sanity limit"));
}

#[test]
fn test_hardening_observability_degraded_capacity_adr0035_af2() {
    let catalog = RunbookCatalogSnapshot::canonical_baseline();
    let mut policy = RunbookSecurityPolicy::default();
    policy.max_active_sessions = 10;

    // Over capacity: 15 active sessions > 10
    let env = RunbookObservabilityService::generate_snapshot_safe(&catalog, &policy, 15);
    assert!(env.ok); // Does not crash or hard fail
    assert!(env.snapshot.is_some());
    let snap = env.snapshot.unwrap();
    assert!(!snap.is_healthy);
    assert_eq!(snap.active_sessions_count, 15);
    assert_eq!(snap.active_sessions_utilization_percent, 150.0);
    // Honest audit row requirement per ADR-0035 AF-2
    assert!(env.audit_row_required);
    assert!(env.error_message.unwrap().contains("exceeds configured policy limit"));
}

#[test]
fn test_hardening_observability_atomic_persistence_and_cleanup() {
    let catalog = RunbookCatalogSnapshot::canonical_baseline();
    let policy = RunbookSecurityPolicy::default();
    let snapshot = RunbookObservabilityService::generate_snapshot(&catalog, &policy, 2).expect("snapshot");

    let temp_dir = std::env::temp_dir();
    let target_file = temp_dir.join(format!("aios_test_obs_hardening_{}.json", std::process::id()));
    let target_path = target_file.to_str().expect("valid path");

    // 1. Atomic write & read
    RunbookObservabilityService::save_snapshot_atomic(target_path, &snapshot).expect("save should succeed");
    let loaded = RunbookObservabilityService::load_snapshot_file(target_path).expect("load should succeed");
    assert_eq!(loaded.total_catalog_runbooks, snapshot.total_catalog_runbooks);
    assert_eq!(loaded.active_sessions_count, snapshot.active_sessions_count);

    // Verify temp file does not remain
    let temp_pattern = format!("{}.tmp.{}", target_path, std::process::id());
    assert!(!std::path::Path::new(&temp_pattern).exists(), "Temp file must be cleaned up");

    // Cleanup target
    let _ = std::fs::remove_file(&target_file);
}

#[test]
fn test_hardening_observability_payload_and_bounds_rejection() {
    let catalog = RunbookCatalogSnapshot::canonical_baseline();
    let policy = RunbookSecurityPolicy::default();
    let mut snapshot = RunbookObservabilityService::generate_snapshot(&catalog, &policy, 1).expect("snapshot");

    // 1. Invalid float bounds
    snapshot.active_sessions_utilization_percent = -5.0;
    assert!(RunbookObservabilityService::validate_snapshot(&snapshot).is_err());

    snapshot.active_sessions_utilization_percent = f64::NAN;
    assert!(RunbookObservabilityService::validate_snapshot(&snapshot).is_err());

    snapshot.active_sessions_utilization_percent = 15_000.0;
    assert!(RunbookObservabilityService::validate_snapshot(&snapshot).is_err());

    // 2. Excess entries
    snapshot.active_sessions_utilization_percent = 50.0;
    let mut large_map = HashMap::new();
    for i in 0..150 {
        large_map.insert(format!("status_{}", i), i);
    }
    snapshot.executions_by_status = large_map;
    assert!(RunbookObservabilityService::validate_snapshot(&snapshot).is_err());
}
