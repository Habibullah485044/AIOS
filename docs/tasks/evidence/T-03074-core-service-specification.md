# Specification: AI Control Plane MCP Server Core Service (T-03074)

**Task ID**: T-03074 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / core service: Specification)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §AF-2, ADR-0037, JSON-RPC 2.0  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: APPROVED — Technical specification and service contract defined for MCP Server Core Service.

---

## 1. Specification Overview

The MCP Server Core Service manages runtime state across the AI Control Plane, providing thread-safe storage of tool catalogs, managing client sessions across initialization and heartbeats, and securely executing tool dispatches.

### Core Service Behaviors
1. **Tool Catalog Management**:
   - Stores up to 256 tools. Rejects duplicate registrations with `MCPSVC_ERR_TOOL_ALREADY_EXISTS`.
   - Thread-safe query and listing returning `Vec<McpToolDefinition>`.
2. **Session Lifecycle Management**:
   - Sessions track client credentials, protocol version, server capabilities, and lifecycle status (`Initializing`, `Active`, `Idle`, `Terminated`).
   - Caps pool at 64 active sessions; rejects over-capacity requests with `MCPSVC_ERR_SESSION_CAPACITY_EXCEEDED`.
3. **Dispatch Execution**:
   - Validates tool presence and arguments.
   - Enforces fail-closed security for capability grants.
   - Wraps output into `McpCoreResultEnvelope`.
