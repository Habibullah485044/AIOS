# Implementation Evidence: AI Control Plane MCP Server Core Service (T-03076)

**Task ID**: T-03076 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / core service: Implementation)  
**Contract Reference**: `docs/tasks/evidence/T-03074-spec.md`  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: COMPLETE — Working implementations of `McpServerCoreService`, thread-safe tool registry, session lifecycle manager, and fail-closed dispatch routing completed across Rust (`aiosh-core`) and Python (`aiosh-mcp`).

---

## 1. Implementation Details

1. **Rust Core Substrate (`code/aiosh-rust/aiosh-core/src/mcp_server_core_service.rs`)**:
   - `McpServerCoreService`: In-memory storage backed by `RwLock<HashMap<String, McpToolDefinition>>` and `RwLock<HashMap<String, McpSessionRecord>>`.
   - Tool operations: `register_tool()`, `unregister_tool()`, `get_tool()`, `list_tools()` (sorted alphabetically). Duplicate detection and capacity enforcement (`MAX_TOOLS_COUNT = 256`).
   - Session operations: `create_session()`, `heartbeat_session()`, `get_session()`, `terminate_session()`. Capacity cap at 64 active sessions with automatic terminated-session eviction.
   - Dispatch pipeline: `dispatch_tool_call()` and `safe_dispatch_tool_call()` wrapping results into `McpCoreResultEnvelope`. Fail-closed rejection of privileged tools without grants.

2. **Python Substrate (`code/aiosh-mcp/aiosh_mcp/mcp_server_core_service.py`)**:
   - Symmetrical class `McpServerCoreService` protected by `threading.Lock`.
   - Tool registration, query, session creation, heartbeat, and termination.
   - Result envelope serialization and fail-closed security gating.

---

## 2. Verification

- Rust tests: `cargo test --test test_mcp_server_core_service_scaffold` -> PASSED (1/1).
- Python tests: `python -m pytest code/aiosh-mcp/tests/test_mcp_server_core_service_scaffold.py` -> PASSED (1/1).
