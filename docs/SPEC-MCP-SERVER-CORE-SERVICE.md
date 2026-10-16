# Specification: AI Control Plane MCP Server Core Service

**Document ID**: SPEC-MCP-SERVER-CORE-SERVICE  
**Lifecycle Target**: T-03073..T-03082 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / core service)  
**Contract Reference**: ADR-0035 §AF-2, ADR-0037, RFC-MCP-CORE-SERVICE-001  
**Status**: ACTIVE  

---

## 1. Overview & Architectural Role

The **MCP Server Core Service** (`McpServerCoreService`) is the core execution coordinator and lifecycle manager for Model Context Protocol (MCP) interactions within AIOS. It provides:
1. An in-memory, thread-safe tool registry supporting up to 256 registered tools.
2. An active session manager handling connection tracking, heartbeats, and bounded capacity (64 concurrent sessions).
3. A fail-closed tool dispatch router enforcing capability grant checks (`grant_id`) on privileged tools (`aios.admin.*`).
4. ADR-0035 §AF-2 standard result envelopment preventing uncaught exceptions or panics across substrates.

Substrate parity is maintained across:
- **Rust Core**: `code/aiosh-rust/aiosh-core/src/mcp_server_core_service.rs`
- **Python Fabric**: `code/aiosh-mcp/aiosh_mcp/mcp_server_core_service.py`
- **FastMCP Bridge**: `code/aiosh-mcp/aiosh_mcp/server.py`

---

## 2. Invariants Certified

- **MCPSVC-INV1 (Thread-Safe Tool Registry)**: Mutex/RwLock-protected catalog capped at `MAX_TOOLS_COUNT = 256`. Duplicate names return `MCPSVC_ERR_TOOL_ALREADY_EXISTS (-32006)`.
- **MCPSVC-INV2 (Bounded Active Sessions Pool)**: Concurrently managed sessions capped at `MAX_ACTIVE_SESSIONS = 64`. Terminated sessions are automatically evicted on pool pressure via `prune_idle_sessions()`.
- **MCPSVC-INV3 (Fail-Closed Dispatch Routing)**: Dispatching an uncataloged tool returns `MCPSVC_ERR_TOOL_NOT_FOUND (-32601)`. Invocations of privileged tools (`aios.admin.*`) lacking a valid capability token fail closed with `ERR_UNAUTHORIZED (-32001)`.
- **MCPSVC-INV4 (ADR-0035 §AF-2 Result Envelope)**: All safe dispatch pathways wrap outputs in deterministic `McpCoreResultEnvelope` objects with clamped timeout boundaries `[1s, 300s]`.
- **MCPSVC-INV5 (Proof-of-Restraint Capability Binding)**: State-changing invocations verify authorization tokens and record audit events before execution.

---

## 3. Sizing Boundaries & Configuration Limits

| Parameter | Value | Description |
| :--- | :--- | :--- |
| `MAX_TOOLS_COUNT` | 256 | Maximum registered tools in service catalog |
| `MAX_ACTIVE_SESSIONS` | 64 | Maximum concurrent active client sessions |
| `SESSION_IDLE_TIMEOUT_SECONDS` | 3600 | Session idle timeout before reclamation |
| `DEFAULT_EXECUTION_TIMEOUT_SECONDS` | 30 | Default dispatch execution timeout |
| `MAX_EXECUTION_TIMEOUT_SECONDS` | 300 | Upper ceiling for dispatch execution |

---

## 4. Error Code Taxonomy

| Code | Constant | Meaning |
| :--- | :--- | :--- |
| `-32001` | `ERR_UNAUTHORIZED` | Privileged tool invoked without valid capability grant |
| `-32002` | `ERR_BOUNDS_EXCEEDED` | Tool registry capacity (256) exceeded |
| `-32004` | `MCPSVC_ERR_SESSION_NOT_FOUND` | Session ID not registered or already terminated |
| `-32005` | `MCPSVC_ERR_SESSION_CAPACITY_EXCEEDED` | Active session limit (64) reached |
| `-32006` | `MCPSVC_ERR_TOOL_ALREADY_EXISTS` | Tool name collision during registration |
| `-32601` | `MCPSVC_ERR_TOOL_NOT_FOUND` | Dispatch target tool does not exist |
| `-32007` | `MCPSVC_ERR_DISPATCH_TIMEOUT` | Execution timed out |

---

## 5. Copy-Pasteable Usage Examples

### Rust Usage

```rust
use aiosh_core::mcp_server_core_service::*;
use aiosh_core::mcp_server_core_data_model::*;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = McpServerCoreService::new();

    // 1. Register a tool
    let tool = McpToolDefinition::new(
        "aios.status.query",
        "Query subsystem status",
        json!({"type": "object"}),
    )?;
    service.register_tool(tool)?;

    // 2. Manage sessions
    let session = service.create_session("sess-001", "desktop-client", "1.0.0")?;
    service.heartbeat_session("sess-001")?;

    // 3. Dispatch tool call safely with timeout
    let call = McpToolCall::new("aios.status.query", json!({}), None)?;
    let result_envelope = service.safe_dispatch_with_timeout(call, 30);
    assert!(result_envelope.ok);

    // 4. Session cleanup
    service.terminate_session("sess-001")?;
    let evicted = service.prune_idle_sessions(0);
    assert_eq!(evicted, 1);

    Ok(())
}
```

### Python Usage

```python
from aiosh_mcp.mcp_server_core_service import (
    McpServerCoreService,
    get_core_service,
)
from aiosh_mcp.mcp_server_core_data_model import (
    McpToolDefinition,
    McpToolCall,
)

service = get_core_service()

# 1. Register a tool
tool = McpToolDefinition(
    name="aios.status.query",
    description="Query subsystem status",
    input_schema={"type": "object"},
)
service.register_tool(tool)

# 2. Manage sessions
session = service.create_session("sess-001", "desktop-client", "1.0.0")
service.heartbeat_session("sess-001")

# 3. Dispatch tool call safely with timeout bounds
call = McpToolCall(name="aios.status.query", arguments={})
envelope = service.safe_dispatch_with_timeout(call, timeout_seconds=30)
assert envelope.ok is True

# 4. Session eviction
service.terminate_session("sess-001")
evicted = service.prune_idle_sessions(max_idle_seconds=0.0)
assert evicted == 1
```

---

## 6. Constraints & Prohibitions

1. **Sampling Disabled**: LLM Sampling is strictly prohibited on server-side dispatches per ADR-0035 §5.
2. **Deterministic Envelopes**: No dispatch call may bubble an uncaught exception or panic to external clients. All outcomes must be enclosed in `McpCoreResultEnvelope`.
3. **Privileged Namespacing**: Any tool prefixed with `aios.admin.` requires a verified `grant_id`.
