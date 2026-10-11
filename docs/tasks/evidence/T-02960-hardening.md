# Hardening Evidence: Compliance Mapping Recovery & Validation (T-02960)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Recovery & Validation
- **Task ID**: `T-02960`
- **Files Modified**:
  - `code/aiosh-rust/aiosh-core/src/compliance_recovery.rs`
  - `code/aiosh-mcp/aiosh_mcp/compliance_recovery.py`

## 1. Hardening Controls Implemented
1. **Quarantine Directory Bounds & File Rotation (CWE-400)**:
   - Added `MAX_QUARANTINE_FILES = 10`.
   - Implemented `prune_old_quarantine_files` in both Rust and Python to automatically prune older `.corrupt.*` quarantine snapshots and prevent disk space exhaustion.
2. **Atomic Backup & Restore Persistence (CWE-362)**:
   - `create_backup` writes first to a unique PID/nanosecond-stamped `.tmp` file, verifies write success, and performs an atomic rename/replace to the `.bak` path.
   - `restore_from_backup` writes to a unique `.tmp` file and performs an atomic rename/replace to the destination catalog.
   - Guaranteed resource cleanup: if any write step fails, the temporary file is unlinked immediately.
3. **Explicit, Auditable Failure Modes**:
   - Standardized machine-readable error codes (`COMPLYREC_ERR_IO`, `COMPLYREC_ERR_PARSE`, `COMPLYREC_ERR_PATH_TRAVERSAL`, `COMPLYREC_ERR_FILE_SIZE`, `COMPLYREC_ERR_VALIDATION`, `COMPLYREC_ERR_NO_BACKUP`).
   - Every failure mode emits an explicit error with an audit row recorded in the audit ring.
   - Zero silent errors or unhandled exceptions across CLI and MCP surfaces.

## 2. Verification Runs
- `cargo test --test test_compliance_recovery_unit --test test_compliance_recovery_integration`: PASS (8/8 tests passed).
- `pytest code/aiosh-mcp/tests/test_compliance_recovery_unit.py code/aiosh-mcp/tests/test_compliance_recovery_integration.py`: PASS (7/7 tests passed).
