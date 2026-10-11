# Integration Evidence: Compliance Mapping Recovery & Validation (T-02958)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Recovery & Validation
- **Task ID**: `T-02958`
- **Files Modified / Created**:
  - `code/aiosh-rust/aiosh-core/src/lib.rs` (re-exported compliance recovery types)
  - `code/aiosh-rust/aiosh-cli/src/main.rs` (wired `verify`, `backup`, `repair`, `restore` commands to `cmd_compliance`, with audit emission and terminal sanitization)
  - `code/aiosh-rust/aiosh-core/tests/test_compliance_recovery_integration.rs` (cross-substrate lifecycle test)
  - `code/aiosh-mcp/tests/test_compliance_recovery_integration.py` (MCP tools integration test)

## 1. Integration Scope & Production Surface
The compliance recovery features are fully integrated into both production caller surfaces:
1. **Rust CLI (`aiosh compliance`)**:
   - `aiosh compliance verify [--json] [--path P]`
   - `aiosh compliance backup [--json] [--path P]`
   - `aiosh compliance repair [--json] [--path P]`
   - `aiosh compliance restore [--json] [--path P]`
   - Integrated with full audit row generation (`classify_and_emit`), deterministic exit codes, and terminal sanitization.
2. **MCP Tool (`compliance`)**:
   - `recovery-verify` (read-only action in `READ_ACTIONS`)
   - `recovery-backup` (gated mutating action in `WRITE_ACTIONS`, requires grant)
   - `recovery-repair` (gated mutating action in `WRITE_ACTIONS`, requires grant)
   - `recovery-restore` (gated mutating action in `WRITE_ACTIONS`, requires grant)

## 2. Verification Results
- **Rust Integration Tests**:
  - `cargo test --test test_compliance_recovery_integration`: PASS (1/1 passed)
  - `cargo test --bin aiosh compliance_cli_tests`: PASS (5/5 passed)
- **Python Integration Tests**:
  - `pytest code/aiosh-mcp/tests/test_compliance_recovery_integration.py`: PASS (1/1 passed)
  - Full compliance suite: `pytest code/aiosh-mcp/tests -k compliance`: PASS (153 passed, 0 failures)
