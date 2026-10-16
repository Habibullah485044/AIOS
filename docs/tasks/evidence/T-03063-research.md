# Research: AI Control Plane MCP Server Core Data Model (T-03063)

**Task ID**: T-03063 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / data model: Research)  
**Contract Reference**: ADR-0035 §D-2, ADR-0037, JSON-RPC 2.0 Specification, Model Context Protocol Spec (2025-06-18)  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: COMPLETE — Authoritative sources surveyed, facts vs assumptions established, architectural decisions documented.

---

## 1. Objective & Scope

Establish the formal domain primitives, data structures, type system, wire envelopes, and safety invariants for the **MCP Server Core Data Model** in AIOS.

As AIOS enters **Phase 3 (AI Control Plane / Pillar C Spine)**, the Model Context Protocol (MCP) server acts as the primary external gateway and command-and-control interface through which language models, AI agents, and orchestration tools interact with AIOS system resources, PEP enforcement engines, and security primitives.

This research establishes:
1. Canonical wire representations (JSON-RPC 2.0 envelopes, MCP requests, responses, and notifications).
2. Domain primitives (Tool definitions, Input schemas, Content blocks, Server capabilities, Client capabilities, Session state).
3. Payload safety limits (maximum message sizes, string length limits, control character sanitization).
4. Dual-substrate symmetry (Rust `aiosh-core` struct/enum models with serde vs Python `aiosh-mcp` data classes).
5. Proof-of-Restraint (PoR) and PEP binding metadata.

---

## 2. Authoritative Sources & Citations

1. **Model Context Protocol (MCP) Specification (Upstream Anthropic / MCP Working Group, 2025-06-18)**:
   - JSON-RPC 2.0 wire format: `jsonrpc: "2.0"`, `id` (string | number), `method: string`, `params?: object`, `result?: object`, `error?: object`.
   - Protocol lifecycle: `initialize` handshake (`protocolVersion`, `capabilities`, `clientInfo`) -> `initialized` notification -> normal operation -> shutdown.
   - Core primitives:
     - `Tool`: `name: string`, `description?: string`, `inputSchema: JSONSchemaObject`.
     - `CallToolRequest`: `name: string`, `arguments?: Record<string, any>`.
     - `CallToolResult`: `content: ContentBlock[]`, `isError?: boolean`.
     - `ContentBlock`: `TextContent` (`type: "text"`, `text: string`), `ImageContent` (`type: "image"`, `data: string`, `mimeType: string`), `EmbeddedResource` (`type: "resource"`, `resource: ResourceContents`).
2. **JSON-RPC 2.0 Specification (RFC 4627 / jsonrpc.org)**:
   - Error code taxonomy:
     - `-32700`: Parse error (invalid JSON received by server).
     - `-32600`: Invalid Request (payload is not a valid Request object).
     - `-32601`: Method not found (requested method does not exist).
     - `-32602`: Invalid params (method arguments invalid).
     - `-32603`: Internal error (internal JSON-RPC server error).
     - `-32000 to -32099`: Server-defined application / transport errors.
3. **AIOS Architectural Decision Records**:
   - **ADR-0035 §D-2**: MCP is the sole tool-call protocol AIOS exposes to external models. The deprecated Sampling primitive is prohibited.
   - **ADR-0035 §AF-2**: Standardized Result Envelope pattern for all service boundaries (`status`, `ok`, `data`, `error`).
   - **ADR-0037**: Proof of Restraint (PoR) Invariant I-2 — every state-changing invocation must bind to an authorization grant, PEP classification, and emit a tamper-evident audit row.

---

## 3. Facts vs. Assumptions

### Facts Established from Codebase
- **Fact 1**: `code/aiosh-mcp/aiosh_mcp/server.py` currently relies on `FastMCP("aiosh-mcp")` with ad-hoc routing. There is no unified, shared Rust-Python data model specifying MCP message types, session descriptors, or wire envelopes.
- **Fact 2**: The Rust core (`code/aiosh-rust/aiosh-core/src/`) currently lacks an `mcp_server_core_data_model.rs` module, meaning protocol verification and serialization must currently occur inside Python without native Rust memory bounds.
- **Fact 3**: Adjacent Phase 2 subsystems (`incident_runbook`, `compliance`, `threat_model`) establish strict data-model invariants (`INV1..INV5`) with constants defining maximum identifier lengths, maximum descriptions, and sanitization for Unicode directional overrides.
- **Fact 4**: The MCP schema version pinned by AIOS is `"2025-06-18"`.

### Assumptions Validated
- **Assumption 1**: The MCP Server Core data model should provide native Rust types in `aiosh-core::mcp_server_core_data_model` and equivalent Python types in `aiosh_mcp.mcp_server_core_data_model`.
- **Assumption 2**: Both substrates must support bidirectional conversion between strongly typed domain representations and serialized JSON-RPC 2.0 strings/dictionaries.
- **Assumption 3**: Envelope bounds must prevent Denial-of-Service (DoS) and memory exhaustion: maximum message size 10 MiB, maximum tool arguments 1 MiB, tool names capped at 64 characters.
- **Assumption 4**: Field validation must reject control characters (`\x00..\x1F`, `\x7F`) and Trojan Source bidirectionality overrides (`\u202A..\u202E`, `\u2066..\u2069`) in tool names, method names, and session IDs.

---

## 4. Key Architectural Decisions Needed

1. **Protocol Schema Modeling**:
   - Model `McpJsonRpcRequest`, `McpJsonRpcResponse`, `McpJsonRpcError`, `McpJsonRpcNotification`.
   - Distinguish request IDs supporting both string IDs (`"req-1"`) and integer IDs (`1`).
2. **Tool Definition & Execution Primitives**:
   - `McpToolDefinition` (`name`, `description`, `input_schema`).
   - `McpToolCall` (`name`, `arguments`, `grant_id`).
   - `McpContentBlock` (`Text`, `Image`, `Resource`).
   - `McpToolResult` (`content`, `is_error`, `meta`).
3. **Session & Capability Primitives**:
   - `McpSessionInfo` (`session_id`, `client_name`, `client_version`, `protocol_version`, `created_at`, `capabilities`).
   - `McpServerCapabilities` (`tools`, `resources`, `prompts`, `logging`).
4. **Result Envelope**:
   - Standardized `McpCoreResultEnvelope<T>` complying with ADR-0035 §AF-2.
