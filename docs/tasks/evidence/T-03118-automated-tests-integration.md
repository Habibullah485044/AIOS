# Integration & Security Audit Evidence: AI Control Plane MCP Server Core Automated Tests (T-03118)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / automated tests
- **Target**: Production server integration with FastMCP (`aiosh_mcp.server`), wire accessibility, and diagnostic tools
- **Spec Reference**: SPEC-MCP-SERVER-CORE-TESTS, ADR-0035 §D-2, PoR Invariant I-2

---

## 1. Production Tool Registration

1. **Integrated Tool**:
   - `aios_mcp_test_run(category: Optional[str] = None)`
   - Exposed on FastMCP stdio server and programmatically callable by diagnostics and audit runners.
   - Accepts category filters (`data_model`, `api`, `service`, `config`, `security`) or defaults to full battery.
2. **Standard Result Format**:
   - Output serialized in standard dictionary envelope: `{"ok": True, "report": McpTestSuiteReport.to_dict()}`.

---

## 2. Security Audit & Invariant Review

- **SA-1 (Safe Diagnostic Execution)**: `aios_mcp_test_run` performs read-only verification with ephemeral in-memory objects. It does not alter active session catalogs, tamper with configurations, or delete audit ring tables.
- **SA-2 (PoR Invariant I-2 Verification)**: Security test category within `aios_mcp_test_run` validates live fail-closed behavior for `aios.admin.*` actions without granting tokens.
- **SA-3 (Failure Containment)**: Any test exception during diagnostic execution is contained within the `McpTestSuiteReport` envelope with `ok=True, report.success=False`, avoiding uncaught daemon crashes.

---

## 3. Test Verification

- **Integration Battery**: `code/aiosh-mcp/tests/test_mcp_server_core_tests_integration.py`
  - `test_mcp_tests_integration_tool_registered` (PASS)
  - `test_mcp_tests_integration_call_all` (PASS)
  - `test_mcp_tests_integration_call_category` (PASS)
  - `test_mcp_tests_integration_invalid_category` (PASS)
- Output: 4 passed in 2.92s.
- **Rust Parity Battery**:
  - `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_mcp_server_core_tests_unit`: 4 passed (0.00s).
