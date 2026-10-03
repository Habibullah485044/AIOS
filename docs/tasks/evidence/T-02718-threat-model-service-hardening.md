# T-02718: Threat Model Maintenance Core Service Hardening

- **Task**: `T-02718`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / core service
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Hardening Scope & Implementations
Addressed the security review findings from T-02717 in `code/aiosh-rust/aiosh-core/src/threat_model_service.rs`:

1. **Atomic Staged Persistence with Collision-Free PID/Timestamp (.tmp)**:
   - Updated `save_to_path` to write to a temporary file named `.{fname}.tmp.{pid}.{nanos}` before performing an atomic `fs::rename`.
   - Temporary file is cleaned up fail-closed in case write or rename encounters an error.
   - Ensures zero file corruption even under abrupt crash or simultaneous writer access.

2. **Symlink and Junction Rejection (CWE-59)**:
   - Added `fs::symlink_metadata` evaluation in `validate_path`.
   - If the target file already exists, confirms it is not a symbolic link or Windows reparse point (`meta.file_type().is_symlink()`), preventing symlink spoofing or arbitrary overwrite outside permitted scopes.

3. **Strict Extension and Depth Bound Enforcement**:
   - Rejects paths without a canonical `.json` extension.
   - Enforces a path component depth limit of `<= 16` to prevent deep traversal and path buffer exhaustion.
   - Rejects empty and whitespace-only path strings.

## 2. Test Verification
All unit tests and integration tests verified clean with 0 failures:
- `test_threat_model_data_model`: 5 passed
- `test_threat_model_integration`: 2 passed
- `test_threat_model_service`: 4 passed
- `test_threat_model_service_integration`: 2 passed
