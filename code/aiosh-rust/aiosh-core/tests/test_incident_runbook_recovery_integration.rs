//! Integration tests for Incident Response Runbooks recovery & validation (T-03058).

use aiosh_core::incident_runbook_recovery::{
    RunbookCatalogStatus, RunbookRecoveryService,
};
use std::fs;
use std::path::Path;

#[test]
fn test_integration_recovery_end_to_end_lifecycle() {
    let tmp_dir = std::env::temp_dir().join(format!("aiosh_rec_integ_{}", std::process::id()));
    let _ = fs::create_dir_all(&tmp_dir);
    let state_file = tmp_dir.join("runbook_state.json");

    // 1. Initial check on missing file
    let check_init = RunbookRecoveryService::validate_state_path(&state_file);
    assert_eq!(check_init.status, RunbookCatalogStatus::Missing);

    // 2. Repair missing file -> reinitializes canonical baseline
    let rep_repair1 = RunbookRecoveryService::repair_runbook_state(&state_file).unwrap();
    assert!(rep_repair1.ok);
    assert_eq!(rep_repair1.action_taken, "canonical_reinitialized");
    assert!(state_file.exists());

    // Verify healthy
    let check_healthy = RunbookRecoveryService::validate_state_path(&state_file);
    assert_eq!(check_healthy.status, RunbookCatalogStatus::Healthy);
    assert_eq!(check_healthy.total_runbooks, 2);

    // 3. Create snapshot backup
    let b_path = RunbookRecoveryService::create_backup(&state_file).unwrap();
    assert!(b_path.exists());

    // 4. Corrupt the state file
    fs::write(&state_file, "corrupt bad json").unwrap();
    let check_corrupt = RunbookRecoveryService::validate_state_path(&state_file);
    assert_eq!(check_corrupt.status, RunbookCatalogStatus::Corrupted);

    // 5. Repair corrupted state -> restores from valid backup
    let rep_repair2 = RunbookRecoveryService::repair_runbook_state(&state_file).unwrap();
    assert!(rep_repair2.ok);
    assert_eq!(rep_repair2.action_taken, "backup_restored");
    assert!(rep_repair2.quarantine_path.is_some());
    assert!(Path::new(&rep_repair2.quarantine_path.unwrap()).exists());

    // 6. Verify restored state is healthy
    let check_restored = RunbookRecoveryService::validate_state_path(&state_file);
    assert_eq!(check_restored.status, RunbookCatalogStatus::Healthy);
    assert_eq!(check_restored.total_runbooks, 2);

    let _ = fs::remove_dir_all(&tmp_dir);
}
