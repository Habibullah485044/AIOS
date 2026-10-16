# Specification: AI Control Plane MCP Server Core Data Model (T-03064)

**Task ID**: T-03064 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / data model: Specification)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §AF-2, ADR-0037, JSON-RPC 2.0  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: APPROVED — Technical specification and domain contract defined for MCP Server Core data model across Rust and Python substrates.

---

## 1. Specification Overview

The Model Context Protocol (MCP) Server Core Data Model formalizes the structures governing communication across the AI Control Plane. It ensures that all tool dispatches, session handshakes, and wire frames adhere to deterministic bounded sizes and cryptographic traceability.

### Key Functional Specifications
1. **JSON-RPC 2.0 Wire Serialization**:
   - `McpRequestId`: String or numeric identifier.
   - `McpJsonRpcRequest`: Validated framing with `jsonrpc: "2.0"`, non-empty method, bounded parameters.
   - `McpJsonRpcResponse`: Standardized success payload (`result`) or structured error (`error`).
   - `McpJsonRpcError`: Strictly mapped to standard JSON-RPC codes (-32700..-32603) and AIOS security error codes (-32001..-32004).

2. **Tool Definition & Invocation**:
   - `McpToolDefinition`: Carries `name`, `description`, and `input_schema` conforming to JSON Schema Draft 7/2020-12.
   - `McpToolCall`: Encapsulates tool invocation arguments with grant authorization context (`grant_id`).
   - `McpContentBlock`: Supports multi-modal responses (`text`, `image`, `resource`).
   - `McpToolResult`: Structured execution output with `is_error` flag and diagnostic metadata.

3. **Session & Security Invariants**:
   - `MCPDM-INV1`: Standard Protocol Conformance (pinned version `"2025-06-18"`).
   - `MCPDM-INV2`: Payload bounds (64-char IDs, 1024-char descriptions, 1 MiB arguments, 10 MiB messages).
   - `MCPDM-INV3`: Unicode sanitization rejecting ASCII control characters and Trojan Source bidi codepoints.
   - `MCPDM-INV4`: Result envelope conformant with ADR-0035 §AF-2.
   - `MCPDM-INV5`: Direct compatibility with Proof-of-Restraint (PoR) audit instrumentation.
