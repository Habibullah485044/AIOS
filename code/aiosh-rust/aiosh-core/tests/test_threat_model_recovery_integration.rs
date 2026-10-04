//! Integration Tests for Threat Model Recovery & Validation (T-02796).

use std::fs;
use tempfile::tempdir;

use aiosh_core::threat_model_config::ThreatModelConfig;
use aiosh_core::threat_model_data_model::*;
use aiosh_core::threat_model_recovery::*;
use aiosh_core::threat_model_service::*;

#[test]
fn test_threat_model_recovery_end_to_end_integration() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().join("threats.json");

    // 1. Initialize configuration and service
    let mut config = ThreatModelConfig::default();
    config.store_path = store_path.clone();
    assert!(config.validate().is_ok());

    let mut service = ThreatModelService::from_config(&config).expect("init service");
    let t1 = ThreatEntry::new(
        "T-INT-001",
        "API Credential Leaking",
        "Leakage of sensitive API keys via headers",
        ThreatCategory::InformationDisclosure,
        ThreatSeverity::High,
        "api_gateway",
        vec!["CWE-200".to_string()],
        vec!["header_scrubbing".to_string()],
    ).unwrap();
    service.register_threat(t1).unwrap();
    service.save_to_path(&store_path).unwrap();

    // 2. Perform non-destructive integrity audit
    let initial_report = ThreatModelService::verify_integrity(&store_path);
    assert_eq!(initial_report.status, ThreatCatalogStatus::Healthy);
    assert_eq!(initial_report.valid_threats, 1);

    // 3. Create snapshot backup
    let backup_path = ThreatRecoveryService::create_backup(&store_path).expect("backup");
    assert!(backup_path.exists());

    // 4. Simulate catastrophic corruption: truncate and append garbage
    fs::write(&store_path, "{\"version\":\"1.0.0\",\"threats\":[ CORRUPT GARBAGE DATA !!!").unwrap();

    // 5. Verify integrity reports corrupted
    let corrupt_report = ThreatModelService::verify_integrity(&store_path);
    assert_eq!(corrupt_report.status, ThreatCatalogStatus::Corrupted);
    assert!(!corrupt_report.issues.is_empty());

    // 6. Execute repair flow
    let repair_report = ThreatModelService::repair_store(&store_path).expect("repair store");
    assert!(repair_report.success);
    assert!(repair_report.quarantined_path.is_some());

    // 7. Post-repair service reload and policy checks
    let reloaded_service = ThreatModelService::from_config(&config).expect("reload after repair");
    assert!(!reloaded_service.snapshot.threats.is_empty());

    // Verify observability reports function cleanly
    let obs_report = reloaded_service.observability_report(None).expect("observability");
    assert!(obs_report.total_threats > 0);
}
