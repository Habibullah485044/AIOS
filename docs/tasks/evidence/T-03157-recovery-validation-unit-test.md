# Unit Test Evidence: AI Control Plane MCP Server Core Recovery & Validation (T-03157)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / recovery & validation
- **Artifact**: `docs/tasks/evidence/T-03157-recovery-validation-unit-test.md`
- **Test Suites Created & Verified**:
  - Python: `code/aiosh-mcp/tests/test_mcp_server_core_recovery_unit.py` (5 passed)
  - Rust: `code/aiosh-rust/aiosh-core/tests/test_mcp_server_core_recovery_unit.rs` (3 passed)

---

## 1. Unit Test Matrix

| Invariant | Test Target | Verification Details | Result |
| :--- | :--- | :--- | :--- |
| **`MCPRECV-INV1`** | Accounting Sum | Asserts `total_records == valid_records + invalid_records` across valid and corrupted reports | **PASS** |
| **`MCPRECV-INV2`** | Health Equivalence | Confirms binary health condition `is_healthy == (len(issues) == 0 and invalid_records == 0)` | **PASS** |
| **`MCPRECV-INV3`** | Non-Destructive Quarantine | Verifies creation of `<path>.bak.<timestamp>` with identical corrupted content | **PASS** |
| **`MCPRECV-INV4`** | Traversal & Bounds | Rejects path traversal (`..`), NUL bytes, and oversized file paths | **PASS** |
| **`MCPRECV-INV5`** | PoR Invariant I-2 Gating | Empty or whitespace capability tokens rejected with `MCPRECV_ERR_UNAUTHORIZED` | **PASS** |
| **Bound Limits** | File Size Ceiling | Files $> 10\text{ MiB}$ flagged with `BOUNDS_EXCEEDED` without unbounded memory read | **PASS** |
