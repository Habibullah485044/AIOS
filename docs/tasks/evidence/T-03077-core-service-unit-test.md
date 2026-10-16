# Unit Test Evidence: AI Control Plane MCP Server Core Service (T-03077)

**Task ID**: T-03077 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / core service: Unit Test)  
**Contract Reference**: `docs/tasks/evidence/T-03074-spec.md`  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: PASSED — 4 Rust unit tests and 4 Python unit tests implemented, covering valid input, invalid input, boundary values, and primary failure modes for `McpServerCoreService`.

---

## 1. Unit Test Matrix

| Case | Category | Description | Rust Result | Python Result |
| :--- | :--- | :--- | :--- | :--- |
| Case 1 | Valid Input | Tool registration, query, list sorting, session lifecycle, heartbeat, dispatch | PASSED | PASSED |
| Case 2 | Invalid Input | Duplicate tool registration, privileged tool call without grant (fail-closed), non-existent session | PASSED | PASSED |
| Case 3 | Boundary Values | Session capacity capping at 64 sessions, overflow rejection, terminated session eviction | PASSED | PASSED |
| Case 4 | Primary Failure Mode | Missing tool dispatch error code (-32601), ADR-0035 §AF-2 envelope wrapping | PASSED | PASSED |

---

## 2. Test Execution Logs

- **Rust Suite**: `cargo test --test test_mcp_server_core_service_unit`
  ```
  running 4 tests
  test test_unit_case1_valid_tool_and_session_lifecycle ... ok
  test test_unit_case2_invalid_input_and_unauthorized_dispatch ... ok
  test test_unit_case4_primary_failure_mode_missing_tool_and_envelope ... ok
  test test_unit_case3_boundary_values_capacity_and_eviction ... ok
  test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.03s
  ```
- **Python Suite**: `pytest code/aiosh-mcp/tests/test_mcp_server_core_service_unit.py`
  ```
  code/aiosh-mcp/tests/test_mcp_server_core_service_unit.py .... [100%]
  4 passed in 0.23s
  ```
