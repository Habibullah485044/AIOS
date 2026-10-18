# Hardening & Security Audit Evidence: AI Control Plane MCP Server Core Automated Tests (T-03120)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / automated tests
- **Target**: Fault containment, diagnostic timeout bounding, error message truncation, and failure envelopment
- **Bindings**: SPEC-MCP-SERVER-CORE-TESTS, ADR-0035 §F-2, PoR Invariant I-2

---

## 1. Hardening & Fault Tolerance Measures

1. **Error Diagnostic Truncation**:
   - In both Python (`mcp_server_core_tests.py`) and Rust (`mcp_server_core_tests.rs`), test failure exception messages are strictly truncated to 1,024 characters.
   - Prevents memory bloat, log injection, and denial of service when serializing large stack traces or memory dumps into `McpTestSuiteReport`.
2. **Category Length and Whitelist Hardening**:
   - `run_category_tests` enforces a 64-character ceiling and strict whitelist validation, immediately rejecting arbitrary, invalid, or oversized category inputs.
3. **Structured Failure Containment**:
   - Diagnostic execution errors never crash the parent server process or thread pool.
   - Failures are wrapped into standard `McpTestSuiteReport` objects with `ok=True, report.success=False`.

---

## 2. Test Verification

- **Python Tests**: `python -m pytest code/aiosh-mcp/tests/test_mcp_server_core_tests_unit.py code/aiosh-mcp/tests/test_mcp_server_core_tests_integration.py` -> 8/8 passed (2.48s).
- **Rust Tests**: `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_mcp_server_core_tests_unit` -> 4/4 passed.
