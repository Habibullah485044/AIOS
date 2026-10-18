# Unit Test & Security Audit Evidence: AI Control Plane MCP Server Core Automated Tests (T-03117)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / automated tests
- **Target**: 4-case unit testing battery covering valid execution, invalid input rejection, boundary values, and primary failure modes across Python and Rust
- **Bindings**: SPEC-MCP-SERVER-CORE-TESTS, ADR-0035 §D-2, PoR Invariant I-2

---

## 1. Unit Test Battery Matrix

1. **Case 1: Valid Execution & Report Serialization**:
   - Executes `run_all_mcp_tests()`, asserting total cases >= 10, 100% pass rate, and zero failures.
   - Asserts individual categories (`data_model`, `api`, `service`, `config`, `security`).
   - Verifies JSON and Markdown serialization of `McpTestSuiteReport`.
2. **Case 2: Invalid Inputs & Error Handling**:
   - Rejects nonexistent or empty category names with explicit `ValueError`.
   - Asserts proper field assignment and validation on malformed inputs.
3. **Case 3: Boundary Values**:
   - Evaluates empty report (0 cases) yielding `success=False`.
   - Evaluates partial failure (1 failed out of 10) yielding `success=False`.
   - Evaluates single passing test yielding `success=True`.
4. **Case 4: Primary Failure Modes**:
   - Validates that assertion errors and unhandled runtime exceptions are trapped by `_execute_test` / `execute_case`, recording `passed=False` and preserving error diagnostics without crashing the suite runner.

---

## 2. Security Audit & Invariants

- **SA-1 (Fail-Safe Reporting)**: The test harness guarantees that failures never fail open or produce false positive reports.
- **SA-2 (PoR Invariant I-2 Assertions)**: Security test category explicitly verifies that unauthenticated access to `aios.admin.*` tools returns `ERR_UNAUTHORIZED` (-32002).
- **SA-3 (No Leaks)**: In-memory executions produce zero leftover mock files or sockets.

---

## 3. Test Verification

- **Python Battery**: `python -m pytest code/aiosh-mcp/tests/test_mcp_server_core_tests_unit.py` -> 4/4 passed (3.16s).
- **Rust Battery**: `cargo test --manifest-path code/aiosh-rust/Cargo.toml --test test_mcp_server_core_tests_unit` -> 4/4 passed.
