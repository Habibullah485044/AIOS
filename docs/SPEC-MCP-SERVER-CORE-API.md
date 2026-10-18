# Specification: AI Control Plane MCP Server Core MCP/API Surface

**Document ID**: SPEC-MCP-SERVER-CORE-API  
**Lifecycle Target**: T-03093..T-03102 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / MCP/API surface)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §AF-2, ADR-0037, JSON-RPC 2.0, PoR Invariant I-2  
**Status**: ACTIVE  

---

## 1. Overview & Architectural Role

The **MCP Server Core MCP/API Surface** specifies the wire-level JSON-RPC 2.0 Model Context Protocol adapter for the AIOS AI Control Plane. It connects host AI clients (IDE assistants, autonomous orchestrators) to the `McpServerCoreService` tool catalog and execution engine.

Both Python (`aiosh_mcp.mcp_server_core_api` / `FastMCP`) and Rust (`aiosh-core::mcp_server_core_api`) adhere strictly to this wire specification.

---

## 2. Protocol Wire Invariants

- **MCPAPI-INV1 (JSON-RPC 2.0 Compliance)**:
  All request and response messages must conform to JSON-RPC 2.0. Responses MUST contain either `result` or `error`, and MUST echo the client's request `id`.
- **MCPAPI-INV2 (Standard Handshake & Method Suite)**:
  The surface handles:
  1. `initialize`: Validates client protocol version, negotiates capabilities, records session.
  2. `ping`: Non-destructive heartbeat liveness check.
  3. `tools/list`: Enumerates tool definitions and schemas.
  4. `tools/call`: Dispatches a tool invocation through the classifier and PEP.
- **MCPAPI-INV3 (Capability Gating & Proof-of-Restraint)**:
  Privileged tools (under `aios.admin.*` or requiring explicit authorizations) MUST provide a valid capability grant. Missing grants trigger refusal and write an audit event.
- **MCPAPI-INV4 (Bounded Allocation & Clamped Timeouts)**:
  Payload sizes are capped at 1 MiB (`MAX_ARGUMENTS_SIZE = 1,048,576 bytes`). Execution timeouts are strictly clamped in `[1, 300]` seconds.
- **MCPAPI-INV5 (Audit Ring Emission)**:
  Every tool dispatch commits an immutable cryptographic audit record into `audit.db` through `AuditRing`.

---

## 3. Wire Format Schema

### 3.1 `initialize`
- Request:
  ```json
  {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-06-18",
      "capabilities": {},
      "clientInfo": { "name": "test-client", "version": "1.0.0" }
    }
  }
  ```
- Response:
  ```json
  {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
      "protocolVersion": "2025-06-18",
      "capabilities": {
        "tools": { "listChanged": false }
      },
      "serverInfo": { "name": "aiosh-mcp", "version": "0.1.0" }
    }
  }
  ```

### 3.2 `tools/call`
- Request:
  ```json
  {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "aios.process.list",
      "arguments": {},
      "grant": null
    }
  }
  ```
- Response (Success):
  ```json
  {
    "jsonrpc": "2.0",
    "id": 2,
    "result": {
      "content": [
        { "type": "text", "text": "{\"ok\": true, \"processes\": []}" }
      ],
      "isError": false
    }
  }
  ```

---

## 4. Error Codes

| Code | Label | Meaning |
| :--- | :--- | :--- |
| `-32700` | Parse Error | Invalid JSON received |
| `-32600` | Invalid Request | Structure violates JSON-RPC 2.0 |
| `-32601` | Method Not Found | Unknown method requested |
| `-32602` | Invalid Params | Missing required arguments or oversized |
| `-32603` | Internal Error | Unhandled server exception |
| `-32001` | Bounds Exceeded | Argument size > 1 MiB or capacity full |
| `-32002` | Unauthorized | Capability grant required or rejected |
