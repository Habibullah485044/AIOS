# Scaffold Evidence: Compliance Mapping Recovery & Validation (T-02955)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Recovery & Validation
- **Task ID**: `T-02955`
- **Files Created / Modified**:
  - `code/aiosh-rust/aiosh-core/src/compliance_recovery.rs` (created typed scaffold)
  - `code/aiosh-rust/aiosh-core/src/lib.rs` (registered `compliance_recovery` module)
  - `code/aiosh-mcp/aiosh_mcp/compliance_recovery.py` (created typed Python scaffold)
  - `code/aiosh-mcp/aiosh_mcp/compliance.py` (added recovery actions: `recovery-verify`, `recovery-backup`, `recovery-repair`, `recovery-restore` and scaffold stubs)
  - `code/aiosh-rust/aiosh-core/tests/test_compliance_recovery_scaffold.rs` (created Rust scaffold test)
  - `code/aiosh-mcp/tests/test_compliance_recovery_scaffold.py` (created Python scaffold test)

## 1. Scaffolded Symbols & Interfaces

### 1.1 Constants & Types
- Error codes: `COMPLYREC_ERR_IO`, `COMPLYREC_ERR_PARSE`, `COMPLYREC_ERR_PATH_TRAVERSAL`, `COMPLYREC_ERR_FILE_SIZE`, `COMPLYREC_ERR_VALIDATION`, `COMPLYREC_ERR_NO_BACKUP`
- Enums: `ComplianceCatalogStatus`, `ComplianceIssueSeverity`, `ComplianceIssueType`
- Structs: `ComplianceIntegrityIssue`, `ComplianceIntegrityReport`, `ComplianceRecoveryAction`, `ComplianceRecoveryReport`
- Service: `ComplianceRecoveryService` (`validate_path`, `verify_integrity`, `create_backup`, `repair_catalog`, `restore_from_backup`)

### 1.2 Verification Runs
- `cargo test --test test_compliance_recovery_scaffold`: PASS
- `python -m pytest code/aiosh-mcp/tests/test_compliance_recovery_scaffold.py`: PASS (2/2 passed)
