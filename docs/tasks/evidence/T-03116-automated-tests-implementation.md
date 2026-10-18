# Implementation & Security Audit Evidence: AI Control Plane MCP Server Core Automated Tests (T-03116)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / automated tests
- **Target**: Unified automated test runner and test matrix implementation across Python and Rust
- **Bindings**: SPEC-MCP-SERVER-CORE-TESTS, ADR-0035 §D-2, PoR Invariant I-2

---

## 1. Implementation Summary

1. **Python Substrate (`aiosh_mcp.mcp_server_core_tests`)**:
   - `_run_data_model_tests()`: Validates tool definition schemas and result envelope formatting.
   - `_run_api_tests()`: Validates JSON-RPC 2.0 `ping`, `initialize`, and method routing.
   - `_run_service_tests()`: Validates tool registry capacity, session lifecycles, and termination.
   - `_run_config_tests()`: Validates configuration defaults and directory traversal rejection.
   - `_run_security_tests()`: Validates PoR Invariant I-2 (`aios.admin.*` requires capability token) and NUL byte rejection.
   - `run_category_tests(category)` & `run_all_mcp_tests()`: Returns structured `McpTestSuiteReport`.
2. **Rust Substrate (`aiosh_core::mcp_server_core_tests`)**:
   - Implemented `run_all_mcp_tests()` executing high-speed test cases across data model, API, service, config, and security categories.
   - Implemented `McpTestSuiteReport` and `McpTestCase` with Serde JSON export and duration benchmarking.

---

## 2. Security Audit & Invariant Enforcement

- **SA-1 (Harness Isolation)**: All test cases instantiate isolated, in-memory service and API handlers. No files are written outside controlled paths.
- **SA-2 (PoR Invariant I-2 Assertions)**: Security category explicitly tests and verifies that unprivileged requests to `aios.admin.*` fail closed with `ERR_UNAUTHORIZED` (-32002).
- **SA-3 (Injection Resistance)**: Asserted rejection of NUL bytes and traversal patterns (`..`) in path arguments.

---

## 3. Test Verification

- **Python Suite**: `python -m pytest code/aiosh-mcp/tests/test_mcp_server_core_tests_impl.py` -> 6/6 passed in 0.35s.
- **Rust Suite**: `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_mcp_server_core_tests_scaffold` -> Verified execution.
