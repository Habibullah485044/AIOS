//! Comprehensive Unit Tests for Compliance Mapping Recovery & Validation (T-02957).

use std::fs;
use aiosh_core::compliance_data_model::*;
use aiosh_core::compliance_recovery::*;

fn make_test_mapping(id: &str, fw: ComplianceFramework, st: ComplianceStatus) -> ComplianceMappingEntry {
    ComplianceMappingEntry::new(
        id,
        "AC-1",
        fw,
        SubstrateTargetType::PepGate,
        "kernel.test.gate",
        vec!["THREAT-01".to_string()],
        st,
        if st == ComplianceStatus::Compliant { "Mitigation documented" } else { "" },
        vec!["unit-test".to_string()],
    )
    .expect("valid entry")
}

#[test]
fn test_recovery_unit_verify_healthy_catalog() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let store_path = temp_dir.path().join("compliance_store.json");

    let mut snap = ComplianceCatalogSnapshot::new("1.0.0");
    snap.add_mapping(make_test_mapping("MAP-REC-01", ComplianceFramework::NistSp80053Rev5, ComplianceStatus::Compliant)).unwrap();
    snap.add_mapping(make_test_mapping("MAP-REC-02", ComplianceFramework::Soc2Type2, ComplianceStatus::PartiallyCompliant)).unwrap();

    let json_bytes = serde_json::to_vec_pretty(&snap).unwrap();
    fs::write(&store_path, json_bytes).unwrap();

    let report = ComplianceRecoveryService::verify_integrity(&store_path);
    assert_eq!(report.status, ComplianceCatalogStatus::Healthy);
    assert_eq!(report.valid_mappings, 2);
    assert_eq!(report.corrupted_mappings, 0);
    assert!(report.issues.is_empty());
}

#[test]
fn test_recovery_unit_verify_missing_file() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let missing_path = temp_dir.path().join("does_not_exist.json");

    let report = ComplianceRecoveryService::verify_integrity(&missing_path);
    assert_eq!(report.status, ComplianceCatalogStatus::Missing);
    assert_eq!(report.valid_mappings, 0);
    assert!(!report.issues.is_empty());
    assert!(report.issues.iter().any(|i| i.issue_type == ComplianceIssueType::MissingCatalogFile));
}

#[test]
fn test_recovery_unit_verify_corrupted_json() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let store_path = temp_dir.path().join("corrupted.json");

    fs::write(&store_path, "{ broken json: true, [ missing").unwrap();

    let report = ComplianceRecoveryService::verify_integrity(&store_path);
    assert_eq!(report.status, ComplianceCatalogStatus::Corrupted);
    assert!(report.issues.iter().any(|i| i.issue_type == ComplianceIssueType::InvalidJsonSyntax));
}

#[test]
fn test_recovery_unit_path_traversal_rejection() {
    let bad_paths = vec![
        std::path::PathBuf::from("../escaped.json"),
        std::path::PathBuf::from("sub/../../escaped.json"),
        std::path::PathBuf::from("\\\\server\\share\\store.json"),
    ];

    for bad_path in bad_paths {
        let err = ComplianceRecoveryService::validate_path(&bad_path);
        assert!(err.is_err(), "Path {:?} should have been rejected", bad_path);
        let msg = err.unwrap_err();
        assert!(msg.contains(COMPLYREC_ERR_PATH_TRAVERSAL));
    }
}

#[test]
fn test_recovery_unit_oversized_file_rejection() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let oversized_path = temp_dir.path().join("oversized.json");

    // Create file exceeding 5MB bound
    let chunk = vec![b'A'; 1024 * 1024]; // 1MB
    let mut file = fs::File::create(&oversized_path).unwrap();
    use std::io::Write;
    for _ in 0..6 {
        file.write_all(&chunk).unwrap();
    }
    drop(file);

    let report = ComplianceRecoveryService::verify_integrity(&oversized_path);
    assert_eq!(report.status, ComplianceCatalogStatus::Corrupted);
    assert!(report.issues.iter().any(|i| i.issue_type == ComplianceIssueType::OversizedPayload));
}

#[test]
fn test_recovery_unit_create_backup_and_restore() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let store_path = temp_dir.path().join("store.json");

    let mut snap = ComplianceCatalogSnapshot::new("1.0.0");
    snap.add_mapping(make_test_mapping("MAP-BAK-01", ComplianceFramework::Iso27001, ComplianceStatus::Compliant)).unwrap();
    fs::write(&store_path, serde_json::to_vec_pretty(&snap).unwrap()).unwrap();

    let backup_path = ComplianceRecoveryService::create_backup(&store_path).expect("create backup");
    assert!(backup_path.exists());

    // Corrupt original file
    fs::write(&store_path, "corrupted content").unwrap();
    let corrupt_report = ComplianceRecoveryService::verify_integrity(&store_path);
    assert_eq!(corrupt_report.status, ComplianceCatalogStatus::Corrupted);

    // Restore from backup
    let restore_report = ComplianceRecoveryService::restore_from_backup(&store_path).expect("restore");
    assert!(restore_report.success);
    assert_eq!(restore_report.mappings_recovered, 1);

    // Re-verify store
    let verified = ComplianceRecoveryService::verify_integrity(&store_path);
    assert_eq!(verified.status, ComplianceCatalogStatus::Healthy);
    assert_eq!(verified.valid_mappings, 1);
}

#[test]
fn test_recovery_unit_repair_salvages_valid_entries() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let store_path = temp_dir.path().join("repairable.json");

    // Construct JSON with 1 valid entry and 1 invalid entry (missing target_ref)
    let json_content = r#"{
      "version": "1.0.0",
      "generated_at": "2026-10-11T00:00:00Z",
      "mappings": [
        {
          "id": "MAP-VALID-01",
          "control_id": "AC-1",
          "framework": "nist_sp_800_53_rev5",
          "target_type": "pep_gate",
          "target_ref": "valid.target.ref",
          "threat_ids": ["T-01"],
          "status": "compliant",
          "mitigation_summary": "Mitigation applied",
          "tags": ["valid"],
          "created_at": "2026-10-11T00:00:00Z",
          "updated_at": "2026-10-11T00:00:00Z"
        },
        {
          "id": "MAP-BAD-02",
          "control_id": "",
          "framework": "nist_sp_800_53_rev5",
          "target_type": "pep_gate",
          "target_ref": "",
          "threat_ids": [],
          "status": "non_compliant",
          "mitigation_summary": "",
          "tags": [],
          "created_at": "2026-10-11T00:00:00Z",
          "updated_at": "2026-10-11T00:00:00Z"
        }
      ]
    }"#;

    fs::write(&store_path, json_content).unwrap();

    let repair_report = ComplianceRecoveryService::repair_catalog(&store_path).expect("repair catalog");
    assert!(repair_report.success);
    assert_eq!(repair_report.mappings_recovered, 1); // 1 salvaged
    assert_eq!(repair_report.mappings_dropped, 1);  // 1 dropped

    // Re-verify
    let verify = ComplianceRecoveryService::verify_integrity(&store_path);
    assert_eq!(verify.status, ComplianceCatalogStatus::Healthy);
    assert_eq!(verify.valid_mappings, 1);
}
