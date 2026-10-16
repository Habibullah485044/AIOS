# Research: AI Control Plane MCP Server Core Data Model (T-03063)

**Task ID**: T-03063 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / data model: Research)  
**Contract Reference**: ADR-0035 §D-2, ADR-0037, JSON-RPC 2.0 Specification, Model Context Protocol Spec (2025-06-18)  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: COMPLETE — Authoritative sources surveyed, facts vs assumptions established, architectural decisions documented.

---

## 1. Research Summary & Background

Phase 3 introduces the AI Control Plane (Pillar C Spine). The central nervous system of this control plane is the **Model Context Protocol (MCP) Server Core**.

The data model provides the bedrock for all JSON-RPC communication between external LLMs, agentic frameworks, and AIOS core kernel components.

### Core Primitives Required
1. **JSON-RPC 2.0 Framing**:
   - `McpRequestId`: String or Int64.
   - `McpJsonRpcRequest`: `jsonrpc: "2.0"`, `id`, `method`, `params`.
   - `McpJsonRpcResponse`: `jsonrpc: "2.0"`, `id`, `result`, `error`.
   - `McpJsonRpcError`: `code`, `message`, `data`.
   - `McpJsonRpcNotification`: `jsonrpc: "2.0"`, `method`, `params`.

2. **Tool Definition & Invocation**:
   - `McpToolDefinition`: `name`, `description`, `input_schema` (JSON schema object).
   - `McpToolCall`: `name`, `arguments` (JSON object), optional `grant_id`.
   - `McpContentBlock`: `TextContent`, `ImageContent`, `ResourceContent`.
   - `McpToolResult`: `content`, `is_error`.

3. **Session & Capabilities**:
   - `McpServerCapabilities`: `tools: bool`, `resources: bool`, `prompts: bool`, `logging: bool`.
   - `McpClientCapabilities`: `roots: bool`, `sampling: bool` (rejected/forbidden per ADR-0035).
   - `McpSessionInfo`: `session_id`, `client_name`, `client_version`, `protocol_version`, `status`.

4. **Invariants (MCPDM-INV1..MCPDM-INV5)**:
   - `MCPDM-INV1`: Wire standard compliance (JSON-RPC 2.0, MCP 2025-06-18).
   - `MCPDM-INV2`: Bounded payload limits (Names <= 64 chars, payloads <= 10 MiB, tool args <= 1 MiB).
   - `MCPDM-INV3`: Unicode sanitization & Trojan Source defense (stripping/rejecting control chars and bidirectional overrides).
   - `MCPDM-INV4`: ADR-0035 §AF-2 Result Envelope standardization.
   - `MCPDM-INV5`: PEP capability and grant integration.

---

## 2. Decision Record for Specification Phase (T-03064)

- **Decisions**:
  - Pinned protocol version: `"2025-06-18"`.
  - Max tool count in list: 256.
  - Max content blocks per result: 32.
  - Safe constructor methods in Rust (`validate()`) and Python (`validate()`) returning explicit error codes.
