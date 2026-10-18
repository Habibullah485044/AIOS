# SPEC-MCP-SERVER-CORE-TESTS: AI Control Plane MCP Server Core Automated Test Subsystem

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / automated tests
- **Status**: Standardized
- **Task**: T-03114
- **Applies to**: `code/aiosh-mcp/aiosh_mcp/mcp_server_core_tests.py`, `code/aiosh-rust/aiosh-core/src/mcp_server_core_tests.rs`

---

## 1. Scope & Objective

This specification formalizes the automated test harness, test execution taxonomy, test case schemas, and reporting contracts for the AI Control Plane MCP Server Core.

---

## 2. Invariants (`MCPTEST-INV1`..`MCPTEST-INV6`)

- **MCPTEST-INV1 (Harness Isolation)**: All test executions and mock stores must operate within temporary directories and release resources upon completion.
- **MCPTEST-INV2 (Determinism)**: Tests must be strictly deterministic and independent of network or ambient environment.
- **MCPTEST-INV3 (Coverage Matrix)**: The battery must cover all four core layers: data model, wire API, core service, and configuration.
- **MCPTEST-INV4 (Security & Invariant Fuzzing)**: The test battery must evaluate input fuzzing (NUL bytes, traversal paths `..`, payload bounds, and privilege gating).
- **MCPTEST-INV5 (Structured Reporting)**: Test runs must yield an auditable `McpTestSuiteReport` envelope.
- **MCPTEST-INV6 (Cross-Substrate Parity)**: Identical test case logic and invariant assertions across Python and Rust implementations.

---

## 3. Data Structures

### 3.1 `McpTestCase`
- `test_id`: `str` — Unique identifier (e.g. `TEST-DATA-01`, `TEST-API-02`).
- `category`: `str` — `data_model` | `api` | `service` | `config` | `security`.
- `name`: `str` — Short descriptive name.
- `passed`: `bool` — Execution outcome.
- `error_message`: `Optional[str]` — Failure reason if failed.
- `duration_ms`: `float` — Execution duration in milliseconds.

### 3.2 `McpTestSuiteReport`
- `suite_name`: `str` — Constant `"mcp_server_core_automated_tests"`.
- `total_cases`: `int` — Count of executed test cases.
- `passed_cases`: `int` — Count of successful test cases.
- `failed_cases`: `int` — Count of failed test cases.
- `success`: `bool` — `true` if `failed_cases == 0`.
- `duration_seconds`: `float` — Total wall-clock time in seconds.
- `cases`: `List[McpTestCase]` — Individual test results.

---

## 4. API Surface

- `run_all_mcp_tests() -> McpTestSuiteReport`
- `run_category_tests(category: str) -> McpTestSuiteReport`
- `McpTestSuiteReport.to_dict() -> Dict[str, Any]`
- `McpTestSuiteReport.to_markdown() -> str`
