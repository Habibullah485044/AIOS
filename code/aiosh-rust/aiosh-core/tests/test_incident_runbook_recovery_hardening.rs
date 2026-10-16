use aiosh_core::incident_runbook_recovery::{
    RunbookCatalogStatus, RunbookRecoveryResultEnvelope, RunbookRecoveryService,
    IRREC_ERR_IO, IRREC_ERR_VALIDATION,
};
use std::fs;

#[test]
fn test_recovery_envelope_types_and_safety() {
    let env_ok = RunbookRecoveryResultEnvelope::success(123);
    assert!(env_ok.ok);
    assert_eq!(env_ok.data, Some(123));
    assert!(!env_ok.audit_row_required);

    let env_err: RunbookRecoveryResultEnvelope<()> =
        RunbookRecoveryResultEnvelope::failure(IRREC_ERR_IO, "Disk full");
    assert!(!env_err.ok);
    assert_eq!(env_err.error_code.as_deref(), Some(IRREC_ERR_IO));
    assert!(env_err.audit_row_required);
}

#[test]
fn test_safe_wrappers_hardening() {
    let tmp_dir = std::env::temp_dir().join(format!("aiosh_rec_harden_{}", std::process::id()));
    let _ = fs::create_dir_all(&tmp_dir);
    let state_file = tmp_dir.join("runbook_state.json");

    // 1. validate_state_path_safe on missing
    let env_missing = RunbookRecoveryService::validate_state_path_safe(&state_file);
    assert!(!env_missing.ok);
    assert!(env_missing.audit_row_required);
    assert_eq!(env_missing.data.unwrap().status, RunbookCatalogStatus::Missing);

    // 2. repair_runbook_state_safe
    let env_repaired = RunbookRecoveryService::repair_runbook_state_safe(&state_file);
    assert!(env_repaired.ok);
    assert_eq!(env_repaired.data.unwrap().action_taken, "canonical_reinitialized");

    // 3. validate_state_path_safe on healthy
    let env_healthy = RunbookRecoveryService::validate_state_path_safe(&state_file);
    assert!(env_healthy.ok);
    assert!(!env_healthy.audit_row_required);

    // 4. create_backup_safe on non-existent file
    let missing_file = tmp_dir.join("missing_never_created.json");
    let env_b_err = RunbookRecoveryService::create_backup_safe(&missing_file);
    assert!(!env_b_err.ok);
    assert_eq!(env_b_err.error_code.as_deref(), Some(IRREC_ERR_IO));
    assert!(env_b_err.audit_row_required);

    // 5. restore_snapshot_safe with corrupted snapshot
    let bad_snap = tmp_dir.join("bad.snap");
    fs::write(&bad_snap, "{corrupt-snap-data").unwrap();
    let env_restore_err = RunbookRecoveryService::restore_snapshot_safe(&bad_snap, &state_file);
    assert!(!env_restore_err.ok);
    assert_eq!(env_restore_err.error_code.as_deref(), Some(IRREC_ERR_VALIDATION));
    assert!(env_restore_err.audit_row_required);

    // 6. Verify zero lingering .tmp files
    let tmp_files_count = fs::read_dir(&tmp_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
        .count();
    assert_eq!(tmp_files_count, 0);

    let _ = fs::remove_dir_all(&tmp_dir);
}
