# Research: AI Control Plane MCP Server Core Service (T-03073)

**Task ID**: T-03073 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / core service: Research)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §AF-2, ADR-0037, Model Context Protocol Spec (2025-06-18)  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: COMPLETE — Authoritative sources surveyed, facts vs assumptions established, architectural decisions documented.

---

## 1. Objective & Scope

Establish the domain architecture, runtime mechanics, session lifecycle management, tool dispatch pipelines, and concurrency controls for the **MCP Server Core Service** in AIOS.

While the data model (T-03063..T-03072) formalizes the types, JSON-RPC 2.0 frames, and wire envelopes, the **core service** provides the active runtime execution engine:
1. Tool registry maintaining active tool definitions, schema validators, and execution handlers.
2. Session lifecycle manager tracking active client connections, capability negotiation state, and heartbeat pings.
3. Secure dispatch router enforcing input validation, bounded timeouts, PEP authorization gating, and Proof-of-Restraint (PoR) audit logging.
4. Concurrency and resource bounds (max active sessions, max concurrent dispatches, session idle timeouts).

---

## 2. Authoritative Sources & Citations

1. **Model Context Protocol (MCP) Specification (2025-06-18)**:
   - Server Request Handling: `initialize`, `ping`, `tools/list`, `tools/call`, `resources/list`, `prompts/list`.
   - Notification Handling: `notifications/initialized`, `notifications/cancelled`, `notifications/progress`.
   - Error Response Semantics: Dispatch errors must return standard JSON-RPC error codes with optional application data envelopes.
2. **AIOS Architectural Decision Records**:
   - **ADR-0035 §D-2**: MCP is the sole external model interface. Deprecated Sampling primitive is prohibited.
   - **ADR-0035 §AF-2**: Standardized Result Envelope pattern for all service boundaries.
   - **ADR-0037**: Proof of Restraint Invariant I-2 — every state-changing dispatch must authenticate a capability grant and log an immutable audit row before execution.
3. **Cross-Subsystem Core Service Prior Art in AIOS**:
   - `incident_runbook_service.rs` / `incident_runbook_service.py`: in-memory session registry with thread-safe RWLock/Mutex, state transitions, bounded active session pools, and canonical baseline fallbacks.
   - `session_service.rs` / `session_service.py`: bounded session timeouts (3600s), session eviction, and client capability reporting.

---

## 3. Facts vs. Assumptions

### Facts Established from Codebase
- **Fact 1**: `code/aiosh-mcp/aiosh_mcp/server.py` hosts a `FastMCP("aiosh-mcp")` application, but currently lacks a dedicated, standalone service layer (`mcp_server_core_service.py` / `mcp_server_core_service.rs`) managing registered tools, session states, and lifecycle transitions programmatically.
- **Fact 2**: The data model (`mcp_server_core_data_model`) establishes wire primitives (`McpJsonRpcRequest`, `McpJsonRpcResponse`, `McpToolDefinition`, `McpToolCall`, `McpSessionInfo`) and sizing constants (`MAX_PAYLOAD_SIZE = 10 MiB`, `MAX_TOOLS_COUNT = 256`).
- **Fact 3**: Adjacent services (`incident_runbook_service`, `privilege_service`, `sandbox_service`) enforce `MAX_ACTIVE_SESSIONS = 64` and maximum idle timeout of 3600 seconds.
- **Fact 4**: All mutations require capability grant tokens (`grant_id`) verified via `_dispatch.py` and committed to the SQLite WAL ring.

### Assumptions Validated
- **Assumption 1**: The MCP core service should be encapsulated as `McpServerCoreService` in Rust (`aiosh-core::mcp_server_core_service`) and Python (`aiosh_mcp.mcp_server_core_service`).
- **Assumption 2**: The service should maintain an internal thread-safe catalog of registered tools (`register_tool`, `get_tool`, `list_tools`) and active sessions (`create_session`, `get_session`, `terminate_session`).
- **Assumption 3**: Dispatching a tool call through `dispatch_tool_call()` must return a standardized `McpCoreResultEnvelope` with execution timing and output content.

---

## 4. Key Architectural Decisions Needed

1. **Session State Machine**:
   - States: `INITIALIZING` -> `ACTIVE` -> `IDLE` -> `TERMINATED`.
   - Max active sessions: 64; automatic pruning of expired/terminated sessions.
2. **Tool Dispatch Engine**:
   - Dynamic registration of native tools with handler callbacks.
   - Bounded execution timeout: 30 seconds default, max 300 seconds.
3. **Error Isolation**:
   - Handler exceptions caught and encapsulated into `McpToolResult` with `is_error: true`, preserving server stability.
