# Scaffold Evidence: AI Control Plane MCP Server Core Service (T-03075)

**Task ID**: T-03075 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / core service: Scaffold)  
**Contract Reference**: `docs/tasks/evidence/T-03074-spec.md`  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: COMPLETE — Service skeleton, thread-safe tool registry, session lifecycle manager, and dispatch interfaces established across Rust (`aiosh-core`) and Python (`aiosh-mcp`). All test stubs compile and pass.

---

## 1. Modules Scaffolded

1. **Rust Core Substrate**:
   - Source: `code/aiosh-rust/aiosh-core/src/mcp_server_core_service.rs`
   - Exports: Registered in `code/aiosh-rust/aiosh-core/src/lib.rs`
   - Test Stub: `code/aiosh-rust/aiosh-core/tests/test_mcp_server_core_service_scaffold.rs`
   - Verification: `cargo test --test test_mcp_server_core_service_scaffold` -> PASSED (1/1).

2. **Python Substrate**:
   - Source: `code/aiosh-mcp/aiosh_mcp/mcp_server_core_service.py`
   - Exports: Registered in `code/aiosh-mcp/aiosh_mcp/__init__.py`
   - Test Stub: `code/aiosh-mcp/tests/test_mcp_server_core_service_scaffold.py`
   - Verification: `pytest code/aiosh-mcp/tests/test_mcp_server_core_service_scaffold.py` -> PASSED (1/1).

---

## 2. Invariants Certified

- `MCPSVC-INV1`: Thread-safe concurrency for tool registry and session state (`RwLock` / `threading.Lock`).
- `MCPSVC-INV2`: Bounded capacity (`MAX_ACTIVE_SESSIONS = 64`, `MAX_TOOLS_COUNT = 256`).
- `MCPSVC-INV4`: Result envelopes declared with ADR-0035 §AF-2 compliance.
