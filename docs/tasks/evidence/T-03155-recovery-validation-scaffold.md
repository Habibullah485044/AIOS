# Scaffold Evidence: AI Control Plane MCP Server Core Recovery & Validation (T-03155)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / recovery & validation
- **Artifact**: `docs/tasks/evidence/T-03155-recovery-validation-scaffold.md`
- **Modules Created**:
  - Python: `code/aiosh-mcp/aiosh_mcp/mcp_server_core_recovery.py`
  - Rust: `code/aiosh-rust/aiosh-core/src/mcp_server_core_recovery.rs`
  - Test: `code/aiosh-mcp/tests/test_mcp_server_core_recovery_scaffold.py`

---

## 1. Scaffold Implementation Details

1. **Python Substrate**:
   - Implemented `McpValidationIssue`, `McpValidationReport` (with invariant verification `MCPRECV-INV1..MCPRECV-INV2`), and `McpRecoveryResult`.
   - Added `validate_store_path` with path traversal rejection, NUL byte detection, and 1024-character bounds check.
   - Added `validate_mcp_store` and `recover_mcp_store` with PoR Invariant I-2 capability token enforcement.
2. **Rust Substrate**:
   - Implemented structs, error enum `McpRecoveryError`, and core routines in `aiosh-core::mcp_server_core_recovery`.
   - Exported `pub mod mcp_server_core_recovery;` in `aiosh-core/src/lib.rs`.
3. **Automated Verification**:
   - Scaffold test suite passed (2/2 tests green).
   - Rust workspace `cargo check` clean (0 errors, 0 warnings).
