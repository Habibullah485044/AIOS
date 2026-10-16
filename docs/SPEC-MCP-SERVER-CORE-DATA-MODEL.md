# Specification: AI Control Plane MCP Server Core Data Model

**Document ID**: SPEC-MCP-SERVER-CORE-DATA-MODEL  
**Lifecycle Target**: T-03063..T-03072 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / data model)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §AF-2, ADR-0037, JSON-RPC 2.0  
**Pinned Protocol Version**: `2025-06-18`  
**Status**: ACTIVE  

---

## 1. Overview & Architectural Role

The **MCP Server Core Data Model** provides the canonical domain primitives, serialization frameworks, and validation logic for AIOS's Model Context Protocol (MCP) server. MCP serves as the unified interface through which external AI models, agentic workflows, and diagnostic tools communicate with the AIOS security kernel and Policy Enforcement Point (PEP) fabric.

The data model is cross-substrate symmetric across:
- **Rust Core**: `code/aiosh-rust/aiosh-core/src/mcp_server_core_data_model.rs`
- **Python Fabric**: `code/aiosh-mcp/aiosh_mcp/mcp_server_core_data_model.py`

---

## 2. Invariants Certified

- **MCPDM-INV1 (Protocol Conformance)**: Strict adherence to JSON-RPC 2.0 framing and the pinned MCP specification version (`2025-06-18`).
- **MCPDM-INV2 (Bounded Wire Payloads)**: Hard bounds preventing memory exhaustion and DoS attacks:
  - Max Message Payload: 10 MiB (`MAX_PAYLOAD_SIZE = 10 * 1024 * 1024`)
  - Max Tool Arguments: 1 MiB (`MAX_ARGUMENTS_SIZE = 1024 * 1024`)
  - Max Tool Name: 64 characters (`MAX_TOOL_NAME_LEN = 64`)
  - Max Tool Description: 1024 characters (`MAX_TOOL_DESC_LEN = 1024`)
  - Max Input Schema Size: 64 KiB (`MAX_SCHEMA_SIZE = 64 * 1024`)
  - Max Session ID: 64 characters (`MAX_SESSION_ID_LEN = 64`)
- **MCPDM-INV3 (Trojan Source & Control Rejection)**: Mandatory rejection of ASCII control characters (`\x00..\x1F`, `\x7F`) and Unicode bidirectional override codepoints (`\u202A..\u202E`, `\u2066..\u2069`). Identifiers must strictly conform to regex `^[a-zA-Z0-9_\.\-]+$`.
- **MCPDM-INV4 (ADR-0035 §AF-2 Result Envelope)**: Deterministic envelope formatting for all responses (`status`, `ok`, `data`, `error_code`, `error_message`, `timestamp`).
- **MCPDM-INV5 (Proof-of-Restraint Capability Binding)**: State-changing invocations must bind to an authorization grant (`grant_id`) and commit an immutable audit row before execution.

---

## 3. Error Code Taxonomy

| Code | Constant | Meaning |
| :--- | :--- | :--- |
| `-32700` | `ERR_PARSE_ERROR` | Invalid JSON received by the server |
| `-32600` | `ERR_INVALID_REQUEST` | The JSON sent is not a valid Request object (e.g. invalid `jsonrpc` version) |
| `-32601` | `ERR_METHOD_NOT_FOUND` | The method does not exist or is not available |
| `-32602` | `ERR_INVALID_PARAMS` | Invalid method parameter or identifier formatting |
| `-32603` | `ERR_INTERNAL_ERROR` | Internal JSON-RPC error |
| `-32001` | `ERR_UNAUTHORIZED` | Capability grant missing or denied by PEP |
| `-32002` | `ERR_BOUNDS_EXCEEDED` | Sizing boundary exceeded (payload, arguments, description) |
| `-32003` | `ERR_SANITIZATION_FAILED` | Identifier contains disallowed control or bidi override characters |
| `-32004` | `ERR_SESSION_EXPIRED` | Requested session ID is expired or invalid |

---

## 4. Copy-Pasteable Usage Examples

### Rust Usage

```rust
use aiosh_core::mcp_server_core_data_model::*;
use serde_json::json;

fn main() {
    // Construct a safe tool definition
    let tool = McpToolDefinition::new(
        "aios.process.list",
        "Inspect active processes safely",
        json!({"type": "object", "properties": {}}),
    ).expect("valid tool");

    // Parse untrusted wire request safely
    let wire_json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let envelope = safe_parse_request_envelope(wire_json);
    assert!(envelope.ok);
    println!("Parsed request id: {:?}", envelope.data.unwrap().id);
}
```

### Python Usage

```python
from aiosh_mcp.mcp_server_core_data_model import (
    McpJsonRpcRequest,
    McpToolDefinition,
    safe_parse_request_envelope,
)

# Parse and validate incoming wire request
wire = '{"jsonrpc": "2.0", "id": "req-1", "method": "tools/list"}'
env = safe_parse_request_envelope(wire)
if env.ok:
    print(f"Validated request: {env.data['id']} -> {env.data['method']}")
else:
    print(f"Error {env.error_code}: {env.error_message}")
```

---

## 5. Known Limitations & Constraints

1. **Protocol Version Lock**: The wire protocol is strictly pinned to version `"2025-06-18"` per ADR-0035 §D-2. Unsolicited upgrades without updating ADR-0035 are rejected.
2. **Sampling Primitive Prohibited**: Per ADR-0035 §5, the MCP Sampling primitive is explicitly forbidden in AIOS to prevent untracked model invocations.
3. **In-Memory Buffer Caps**: Stream-based chunking is not provided for payloads exceeding 10 MiB; clients must segment large data transfers.
