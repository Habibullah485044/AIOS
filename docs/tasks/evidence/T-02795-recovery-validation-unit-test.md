# Unit Test Evidence: Threat Model Maintenance Recovery & Validation (T-02795)

- **Task ID**: T-02795
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Maintenance / recovery & validation
- **Status**: Completed
- **Document Date**: 2026-10-04

## 1. Test Suite Coverage
Implemented unit tests in `code/aiosh-rust/aiosh-core/tests/test_threat_model_recovery.rs`:
- `test_recovery_non_existent_file`: Verified handling of missing files, auditing status as `Missing`, and successful auto-healing via canonical STRIDE baseline seeding.
- `test_recovery_healthy_store`: Asserted clean status on healthy catalogs without false-positive corruption alerts.
- `test_recovery_path_traversal_rejection`: Validated rejection of path traversal (`..`) patterns and emission of `THREATREC_ERR_PATH_TRAVERSAL`.
- `test_recovery_backup_and_restore`: Created point-in-time `.bak` snapshots and verified full restoration after simulated mutation.
- `test_recovery_corrupted_json_salvage`: Asserted quarantine creation for unparseable JSON files and fallback recovery.
- `test_recovery_partial_corrupted_entries_salvage`: Tested granular salvage of valid threat entries while isolating and dropping corrupt entries.

## 2. Test Execution
Verified all 6 test cases pass isolated execution under `cargo test -p aiosh-core --test test_threat_model_recovery`.
