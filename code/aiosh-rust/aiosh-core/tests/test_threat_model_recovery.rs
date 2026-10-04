//! Unit Tests for Threat Model Maintenance Recovery & Validation (T-02795).

use std::fs;
use tempfile::tempdir;

use aiosh_core::threat_model_data_model::*;
use aiosh_core::threat_model_recovery::*;
use aiosh_core::threat_model_service::*;

#[test]
fn test_recovery_non_existent_file() {
    let dir = tempdir().unwrap();
    let missing_path = dir.path().join("missing_threats.json");

    let report = ThreatRecoveryService::verify_integrity(&missing_path);
    assert_eq!(report.status, ThreatCatalogStatus::Missing);
    assert_eq!(report.total_threats, 0);
    assert!(!report.has_backup);

    // Repairing missing file seeds canonical baseline
    let repair = ThreatRecoveryService::repair_catalog(&missing_path).expect("repair missing file");
    assert!(repair.success);
    assert!(missing_path.exists());
    assert!(repair.threats_recovered > 0);

    let verify_after = ThreatRecoveryService::verify_integrity(&missing_path);
    assert_eq!(verify_after.status, ThreatCatalogStatus::Healthy);
}

#[test]
fn test_recovery_healthy_store() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().join("threats.json");

    let svc = ThreatModelService::with_canonical_threats();
    svc.save_to_path(&store_path).unwrap();

    let report = ThreatRecoveryService::verify_integrity(&store_path);
    assert_eq!(report.status, ThreatCatalogStatus::Healthy);
    assert!(report.total_threats > 0);
    assert_eq!(report.corrupted_threats, 0);
    assert!(report.issues.is_empty());
}

#[test]
fn test_recovery_path_traversal_rejection() {
    let dir = tempdir().unwrap();
    let malicious_path = dir.path().join("../etc/passwd.json");

    let report = ThreatRecoveryService::verify_integrity(&malicious_path);
    assert_eq!(report.status, ThreatCatalogStatus::Corrupted);
    assert!(report.issues.iter().any(|i| i.issue_type == ThreatIssueType::InvalidPathTraversal));

    let res = ThreatRecoveryService::create_backup(&malicious_path);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("THREATREC_ERR_PATH_TRAVERSAL"));
}

#[test]
fn test_recovery_backup_and_restore() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().join("threats.json");

    let mut svc = ThreatModelService::new();
    let t = ThreatEntry::new(
        "T-TEST-001",
        "Test Threat",
        "Test threat description",
        ThreatCategory::Spoofing,
        ThreatSeverity::High,
        "auth",
        vec!["CWE-287".to_string()],
        vec!["mfa".to_string()],
    ).unwrap();
    svc.register_threat(t).unwrap();
    svc.save_to_path(&store_path).unwrap();

    // Create backup
    let backup_path = ThreatRecoveryService::create_backup(&store_path).expect("create backup");
    assert!(backup_path.exists());

    // Modify original store
    let mut modified_svc = ThreatModelService::new();
    let t2 = ThreatEntry::new(
        "T-TEST-002",
        "Another Threat",
        "Another threat description",
        ThreatCategory::Tampering,
        ThreatSeverity::Critical,
        "db",
        vec!["CWE-89".to_string()],
        vec!["sql_prep".to_string()],
    ).unwrap();
    modified_svc.register_threat(t2).unwrap();
    modified_svc.save_to_path(&store_path).unwrap();

    // Restore from backup
    let restore = ThreatRecoveryService::restore_from_backup(&store_path).expect("restore from backup");
    assert!(restore.success);
    assert_eq!(restore.threats_recovered, 1);

    // Verify restored store matches original T-TEST-001
    let loaded = ThreatModelService::load_from_path(&store_path).unwrap();
    assert_eq!(loaded.snapshot.threats.len(), 1);
    assert_eq!(loaded.snapshot.threats[0].id, "T-TEST-001");
}

#[test]
fn test_recovery_corrupted_json_salvage() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().join("corrupted.json");

    // Completely unparseable JSON
    fs::write(&store_path, "{ broken json content !! ").unwrap();

    let report = ThreatRecoveryService::verify_integrity(&store_path);
    assert_eq!(report.status, ThreatCatalogStatus::Corrupted);
    assert!(report.issues.iter().any(|i| i.issue_type == ThreatIssueType::InvalidJsonSyntax));

    let repair = ThreatRecoveryService::repair_catalog(&store_path).expect("repair corrupt file");
    assert!(repair.success);
    assert!(repair.quarantined_path.is_some());
    assert!(std::path::Path::new(repair.quarantined_path.as_ref().unwrap()).exists());

    // After repair, file is healthy (canonical fallback)
    let verify_after = ThreatRecoveryService::verify_integrity(&store_path);
    assert_eq!(verify_after.status, ThreatCatalogStatus::Healthy);
}

#[test]
fn test_recovery_partial_corrupted_entries_salvage() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().join("partial_corrupt.json");

    // JSON containing one valid threat and one invalid threat (invalid ID format)
    let json_data = r#"{
        "version": "1.0.0",
        "generated_at": "2026-10-04T00:00:00Z",
        "threats": [
            {
                "id": "T-VALID-01",
                "title": "Valid Threat",
                "description": "Valid description",
                "category": "spoofing",
                "severity": "medium",
                "status": "identified",
                "component": "net",
                "cwe_ids": ["CWE-290"],
                "mitigations": ["tls"],
                "created_at": "2026-10-04T00:00:00Z",
                "updated_at": "2026-10-04T00:00:00Z"
            },
            {
                "id": "INVALID ID WITH SPACES $$$",
                "title": "Corrupt Threat",
                "description": "Some description",
                "category": "tampering",
                "severity": "high",
                "status": "identified",
                "component": "fs",
                "cwe_ids": [],
                "mitigations": [],
                "created_at": "2026-10-04T00:00:00Z",
                "updated_at": "2026-10-04T00:00:00Z"
            }
        ]
    }"#;
    fs::write(&store_path, json_data).unwrap();

    let report = ThreatRecoveryService::verify_integrity(&store_path);
    assert_eq!(report.status, ThreatCatalogStatus::Degraded);
    assert_eq!(report.total_threats, 2);
    assert_eq!(report.valid_threats, 1);
    assert_eq!(report.corrupted_threats, 1);

    let repair = ThreatRecoveryService::repair_catalog(&store_path).expect("repair partial");
    assert!(repair.success);
    assert_eq!(repair.threats_recovered, 1);
    assert_eq!(repair.threats_dropped, 1);

    // Verify resulting store only has the valid threat
    let loaded = ThreatModelService::load_from_path(&store_path).unwrap();
    assert_eq!(loaded.snapshot.threats.len(), 1);
    assert_eq!(loaded.snapshot.threats[0].id, "T-VALID-01");
}

#[test]
fn test_recovery_oversized_payload_rejection() {
    let dir = tempdir().unwrap();
    let oversized_path = dir.path().join("oversized.json");

    // Write file exceeding 1 MiB
    let big_buffer = vec![b' '; (MAX_THREAT_MODEL_STORE_SIZE + 1024) as usize];
    fs::write(&oversized_path, big_buffer).unwrap();

    let report = ThreatRecoveryService::verify_integrity(&oversized_path);
    assert_eq!(report.status, ThreatCatalogStatus::Corrupted);
    assert!(report.issues.iter().any(|i| i.issue_type == ThreatIssueType::OversizedPayload));
}

#[test]
fn test_recovery_no_temp_leak_on_repair() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().join("threats.json");

    let svc = ThreatModelService::with_canonical_threats();
    svc.save_to_path(&store_path).unwrap();

    let repair = ThreatRecoveryService::repair_catalog(&store_path).expect("repair");
    assert!(repair.success);

    // Assert no leftover temporary files in directory
    for entry in fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        let fname = entry.file_name().to_string_lossy().to_string();
        assert!(!fname.contains(".tmp."), "Found leaked temporary file: {}", fname);
    }
}

