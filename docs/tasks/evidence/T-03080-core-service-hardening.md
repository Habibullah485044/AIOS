# Hardening Evidence: AI Control Plane MCP Server Core Service (T-03080)

**Task ID**: T-03080 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / core service: Hardening)  
**Contract Reference**: `docs/tasks/evidence/T-03074-spec.md`, ADR-0035 §AF-2  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: PASSED — Hardened session lifecycle eviction (`prune_idle_sessions`), bounded dispatch timeouts (`safe_dispatch_with_timeout`), and ADR-0035 §AF-2 result envelopes verified across Rust (`aiosh-core`) and Python (`aiosh-mcp`).

---

## 1. Hardening Mitigations Delivered

1. **Session Eviction and Leak Prevention (MCPSVC-INV2)**:
   - Added `prune_idle_sessions(max_idle_seconds)` to `McpServerCoreService` in both Rust (`aiosh-core`) and Python (`aiosh-mcp`).
   - Automatically sweeps and frees terminated sessions and expired idle sessions under pool pressure, ensuring the active pool remains strictly bounded by `MAX_ACTIVE_SESSIONS = 64`.

2. **Timeout Clamping & Safe Execution Dispatch (MCPSVC-INV4)**:
   - Added `safe_dispatch_with_timeout(call, timeout_seconds)` enforcing lower and upper timeout boundaries `[1s, 300s]` (`MAX_EXECUTION_TIMEOUT_SECONDS`).
   - Dispatches return standardized `McpCoreResultEnvelope` with fail-closed JSON-RPC error codes (`MCPSVC_ERR_TOOL_NOT_FOUND = -32601`, `ERR_UNAUTHORIZED = -32001`) preventing uncaught panics or exceptions.

3. **Concurrency and State Integrity (MCPSVC-INV1)**:
   - Guaranteed thread safety via `RwLock` in Rust and re-entrant locking in Python across registration, lookup, eviction, and dispatch.

---

## 2. Hardening Test Battery Execution

- **Rust Suite**: `cargo test --test test_mcp_server_core_service_hardening`
  ```
  running 2 tests
  test test_hardening_prune_idle_and_terminated_sessions ... ok
  test test_hardening_safe_dispatch_timeout_and_fault_tolerance ... ok
  test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
  ```

- **Python Suite**: `pytest code/aiosh-mcp/tests/test_mcp_server_core_service_hardening.py`
  ```
  code\aiosh-mcp\tests\test_mcp_server_core_service_hardening.py .. [100%]
  2 passed in 0.79s
  ```
