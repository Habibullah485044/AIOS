# Implementation Evidence: AI Control Plane MCP Server Core Recovery & Validation (T-03156)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / recovery & validation
- **Artifact**: `docs/tasks/evidence/T-03156-recovery-validation-implementation.md`
- **Modules Verified**:
  - `code/aiosh-mcp/aiosh_mcp/mcp_server_core_recovery.py`
  - `code/aiosh-rust/aiosh-core/src/mcp_server_core_recovery.rs`
  - `code/aiosh-mcp/tests/test_mcp_server_core_recovery_impl.py`

---

## 1. Implementation Details

1. **Deep State Store Validation**:
   - `validate_mcp_store` checks file existence, size constraints (`MAX_STORE_FILE_BYTES = 10 MiB`), and root JSON object structures.
   - Enforces mathematical invariant conservation: `total_records == valid_records + invalid_records`.
   - Enforces binary health equivalence: `is_healthy == (len(issues) == 0 and invalid_records == 0)`.
2. **Non-Destructive Quarantine Recovery**:
   - `recover_mcp_store` safely copies corrupted state files into `<path>.bak.<timestamp>` with `0600` permissions.
   - Atomically provisions a fresh valid store via PID-tagged temporary files with replacement.
3. **Proof-of-Restraint Gating (PoR Invariant I-2)**:
   - State repair operations strictly require non-empty capability tokens, raising `PermissionError` when omitted.
4. **Automated Verification**:
   - `test_mcp_server_core_recovery_impl.py`: 4/4 tests PASSED.
