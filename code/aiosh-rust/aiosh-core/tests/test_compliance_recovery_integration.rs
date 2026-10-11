//! Cross-substrate Integration Tests for Compliance Mapping Recovery & Validation (T-02958).

use std::fs;
use aiosh_core::compliance_data_model::*;
use aiosh_core::compliance_recovery::*;
use aiosh_core::compliance_service::ComplianceService;

#[test]
fn test_recovery_integration_cross_substrate_lifecycle() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let store_path = temp_dir.path().join("compliance_map.json");

    // 1. Initialize with canonical baseline
    let base_svc = ComplianceService::with_canonical_baseline();
    base_svc.save_to_path(&store_path).expect("save initial catalog");

    // 2. Pre-backup verification
    let report_initial = ComplianceRecoveryService::verify_integrity(&store_path);
    assert_eq!(report_initial.status, ComplianceCatalogStatus::Healthy);
    assert_eq!(report_initial.valid_mappings, 4);
    assert!(!report_initial.has_backup);

    // 3. Create backup snapshot
    let backup_path = ComplianceRecoveryService::create_backup(&store_path).expect("create backup");
    assert!(backup_path.exists());

    // 4. Verify post-backup status flags has_backup
    let report_after_backup = ComplianceRecoveryService::verify_integrity(&store_path);
    assert!(report_after_backup.has_backup);
    assert_eq!(report_after_backup.backup_path, Some(backup_path.to_string_lossy().to_string()));

    // 5. Corrupt active store with malformed content
    fs::write(&store_path, "MALFORMED_HEADER_DATA_NOT_JSON").unwrap();
    let report_corrupted = ComplianceRecoveryService::verify_integrity(&store_path);
    assert_eq!(report_corrupted.status, ComplianceCatalogStatus::Corrupted);

    // 6. Restore from backup
    let restore_result = ComplianceRecoveryService::restore_from_backup(&store_path).expect("restore from backup");
    assert!(restore_result.success);
    assert_eq!(restore_result.mappings_recovered, 4);

    // 7. Verify restored catalog is 100% healthy
    let report_restored = ComplianceRecoveryService::verify_integrity(&store_path);
    assert_eq!(report_restored.status, ComplianceCatalogStatus::Healthy);
    assert_eq!(report_restored.valid_mappings, 4);
    assert_eq!(report_restored.corrupted_mappings, 0);

    // 8. Test repair on partially corrupted catalog
    let mut snap = serde_json::from_str::<ComplianceCatalogSnapshot>(&fs::read_to_string(&store_path).unwrap()).unwrap();
    // Inject corrupt entry with empty fields
    snap.mappings.push(ComplianceMappingEntry {
        id: "MAP-CORRUPT-ENTRY".to_string(),
        control_id: "".to_string(),
        framework: ComplianceFramework::NistSp80053Rev5,
        target_type: SubstrateTargetType::PepGate,
        target_ref: "".to_string(),
        threat_ids: vec![],
        status: ComplianceStatus::NonCompliant,
        mitigation_summary: "".to_string(),
        tags: vec![],
        created_at: "".to_string(),
        updated_at: "".to_string(),
    });
    fs::write(&store_path, serde_json::to_vec_pretty(&snap).unwrap()).unwrap();

    let report_degraded = ComplianceRecoveryService::verify_integrity(&store_path);
    assert_eq!(report_degraded.status, ComplianceCatalogStatus::Degraded);
    assert_eq!(report_degraded.valid_mappings, 4);
    assert_eq!(report_degraded.corrupted_mappings, 1);

    let repair_report = ComplianceRecoveryService::repair_catalog(&store_path).expect("repair degraded");
    assert!(repair_report.success);
    assert_eq!(repair_report.mappings_recovered, 4);
    assert_eq!(repair_report.mappings_dropped, 1);
    assert!(repair_report.quarantined_path.is_some());

    // 9. Verify quarantined file exists and matches corrupt version
    let q_path = std::path::PathBuf::from(repair_report.quarantined_path.unwrap());
    assert!(q_path.exists());

    // 10. Post-repair catalog is clean
    let final_report = ComplianceRecoveryService::verify_integrity(&store_path);
    assert_eq!(final_report.status, ComplianceCatalogStatus::Healthy);
    assert_eq!(final_report.valid_mappings, 4);
}
