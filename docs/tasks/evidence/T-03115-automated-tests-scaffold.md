# Scaffold & Security Audit Evidence: AI Control Plane MCP Server Core Automated Tests (T-03115)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / automated tests
- **Target**: Module skeleton, test case definitions, test suite report envelopes, and fail-loudly stubs
- **Bindings**: SPEC-MCP-SERVER-CORE-TESTS, PoR Invariant I-2

---

## 1. Scaffold Implementation

1. **Python Substrate (`aiosh_mcp.mcp_server_core_tests`)**:
   - `McpTestCategory`: Enum representing test domain classification (`data_model`, `api`, `service`, `config`, `security`).
   - `McpTestCase`: Structured test record with test identifier, category, duration, and pass/fail state.
   - `McpTestSuiteReport`: Standard report envelope providing JSON and Markdown rendering.
   - Stubbed runners: `run_category_tests()` and `run_all_mcp_tests()` failing loudly with `NotImplementedError`.
2. **Rust Substrate (`aiosh_core::mcp_server_core_tests`)**:
   - Strongly-typed structs with Serde serialization support (`McpTestCategory`, `McpTestCase`, `McpTestSuiteReport`).
   - `run_all_mcp_tests()` stub returning `Err` with descriptive scaffold message.
   - Registered in `code/aiosh-rust/aiosh-core/src/lib.rs`.

---

## 2. Security Audit & Invariant Checks

- **Audit Item 1 (Zero Ambient Side Effects)**: Verified that types and stub functions do not perform disk mutations, external network I/O, or persistent process execution.
- **Audit Item 2 (Standard Fail-Safe Signatures)**: Unimplemented routines fail loudly, preventing silent mock passes or bypassed tests.

---

## 3. Test Verification

- **Python Scaffold**: `python -m pytest code/aiosh-mcp/tests/test_mcp_server_core_tests_scaffold.py` -> 2/2 passed.
- **Rust Scaffold**: Verified via `code/aiosh-rust/aiosh-core/tests/test_mcp_server_core_tests_scaffold.rs`.
