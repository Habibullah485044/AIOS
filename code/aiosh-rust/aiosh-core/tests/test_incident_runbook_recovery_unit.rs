use aiosh_core::incident_runbook_data_model::RunbookCatalogSnapshot;
use aiosh_core::incident_runbook_recovery::{
    RunbookCatalogStatus, RunbookIssueType, RunbookRecoveryService,
    MAX_QUARANTINE_FILES, MAX_RUNBOOK_STATE_SIZE,
};
use std::fs;
use std::path::Path;

#[test]
fn test_unit_case1_valid_input_catalog_and_backup() {
    let tmp_dir = std::env::temp_dir().join(format!("aiosh_rec_test_valid_{}", std::process::id()));
    let _ = fs::create_dir_all(&tmp_dir);
    let state_file = tmp_dir.join("runbook_state.json");

    // Write canonical catalog
    let canonical = RunbookCatalogSnapshot::canonical_baseline();
    let json_data = serde_json::to_string_pretty(&canonical).unwrap();
    fs::write(&state_file, json_data).unwrap();

    // Validate state
    let rep = RunbookRecoveryService::validate_state_path(&state_file);
    assert_eq!(rep.status, RunbookCatalogStatus::Healthy);
    assert!(rep.issues.is_empty());
    assert_eq!(rep.total_runbooks, canonical.runbooks.len());

    // Create backup
    let b_path = RunbookRecoveryService::create_backup(&state_file).unwrap();
    assert!(b_path.exists());

    // Repair on healthy should be noop
    let repair_rep = RunbookRecoveryService::repair_runbook_state(&state_file).unwrap();
    assert!(repair_rep.ok);
    assert_eq!(repair_rep.action_taken, "noop");

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_unit_case2_invalid_input_path_traversal_and_malformed_json() {
    // Path traversal check
    let invalid_path = Path::new("../../etc/passwd");
    let rep = RunbookRecoveryService::validate_state_path(invalid_path);
    assert_eq!(rep.status, RunbookCatalogStatus::Corrupted);
    assert!(rep.issues.iter().any(|i| i.issue_type == RunbookIssueType::InvalidPathTraversal));
    assert!(!rep.is_recoverable);

    // Malformed JSON check
    let rep_json = RunbookRecoveryService::validate_runbook_json("{not-valid-json", "test_path");
    assert_eq!(rep_json.status, RunbookCatalogStatus::Corrupted);
    assert!(rep_json.issues.iter().any(|i| i.issue_type == RunbookIssueType::InvalidJsonSyntax));

    // Duplicate ID check
    let mut canonical = RunbookCatalogSnapshot::canonical_baseline();
    let dup_entry = canonical.runbooks[0].clone();
    canonical.runbooks.push(dup_entry);
    let dup_json = serde_json::to_string(&canonical).unwrap();
    let rep_dup = RunbookRecoveryService::validate_runbook_json(&dup_json, "test_dup");
    assert_eq!(rep_dup.status, RunbookCatalogStatus::Degraded);
    assert!(rep_dup.issues.iter().any(|i| i.issue_type == RunbookIssueType::DuplicateRunbookId));
}

#[test]
fn test_unit_case3_boundary_values_payload_limit_and_quarantine_rotation() {
    let tmp_dir = std::env::temp_dir().join(format!("aiosh_rec_test_bounds_{}", std::process::id()));
    let _ = fs::create_dir_all(&tmp_dir);

    // Oversized payload check
    let rep_size = RunbookRecoveryService::validate_runbook_json(
        &"x".repeat((MAX_RUNBOOK_STATE_SIZE + 1) as usize),
        "test_oversized",
    );
    assert_eq!(rep_size.status, RunbookCatalogStatus::Corrupted);
    assert!(rep_size.issues.iter().any(|i| i.issue_type == RunbookIssueType::OversizedPayload));

    // Quarantine file rotation check
    let base_file = tmp_dir.join("test_runbook.json");
    fs::write(&base_file, "corrupt").unwrap();

    // Create 15 quarantine files
    for i in 0..15 {
        let q_file = tmp_dir.join(format!("test_runbook.json.corrupt.100.{}", i));
        fs::write(&q_file, format!("quarantine {}", i)).unwrap();
    }

    let pruned = RunbookRecoveryService::prune_old_quarantine_files(&tmp_dir, "test_runbook.json");
    assert_eq!(pruned, 5);

    // Remaining quarantine files count should be MAX_QUARANTINE_FILES (10)
    let remaining = fs::read_dir(&tmp_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".corrupt."))
        .count();
    assert_eq!(remaining, MAX_QUARANTINE_FILES);

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_unit_case4_primary_failure_mode_corrupted_state_repaired() {
    let tmp_dir = std::env::temp_dir().join(format!("aiosh_rec_test_repair_{}", std::process::id()));
    let _ = fs::create_dir_all(&tmp_dir);
    let state_file = tmp_dir.join("runbook_state.json");

    // Seed file with corrupted data
    fs::write(&state_file, "{corrupted broken content!!!").unwrap();

    // Repair corrupted state
    let rep = RunbookRecoveryService::repair_runbook_state(&state_file).unwrap();
    assert!(rep.ok);
    assert_eq!(rep.action_taken, "canonical_reinitialized");
    assert!(rep.quarantine_path.is_some());
    assert!(Path::new(&rep.quarantine_path.unwrap()).exists());

    // Verified state is now healthy
    let check_rep = RunbookRecoveryService::validate_state_path(&state_file);
    assert_eq!(check_rep.status, RunbookCatalogStatus::Healthy);
    assert_eq!(check_rep.total_runbooks, 2);

    let _ = fs::remove_dir_all(&tmp_dir);
}
