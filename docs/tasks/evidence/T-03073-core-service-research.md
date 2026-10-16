# Research: AI Control Plane MCP Server Core Service (T-03073)

**Task ID**: T-03073 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / core service: Research)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §AF-2, ADR-0037, Model Context Protocol Spec (2025-06-18)  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: COMPLETE — Authoritative sources surveyed, facts vs assumptions established, architectural decisions documented.

---

## 1. Research Summary & Architecture

The MCP Server Core Service provides the execution backbone of Phase 3 (AI Control Plane). It manages active tool registries, client session tracking, request dispatch routing, and PEP audit binding.

### Key Service Primitives Required
1. **Tool Registry**:
   - Thread-safe storage of up to 256 tool definitions.
   - Dynamic registration with duplicate detection.
   - Lookup by canonical tool identifier (e.g. `aios.fs.read`).
2. **Session Manager**:
   - Session tracking with unique session IDs.
   - State lifecycle: `Initializing`, `Active`, `Idle`, `Terminated`.
   - Bounded session capacity (`MAX_ACTIVE_SESSIONS = 64`) with eviction of terminated sessions.
3. **Dispatch Pipeline**:
   - Verification of incoming `McpToolCall` against registered tool schema.
   - Invocation routing returning `McpToolResult` wrapped in `McpCoreResultEnvelope`.
   - PEP authorization token validation and tamper-evident audit logging.
4. **Service Invariants (MCPSVC-INV1..MCPSVC-INV5)**:
   - `MCPSVC-INV1`: Thread-safe concurrency for tool and session maps.
   - `MCPSVC-INV2`: Deterministic session state transitions and bounded pool size.
   - `MCPSVC-INV3`: Fail-closed routing (unregistered tools or missing grants rejected).
   - `MCPSVC-INV4`: ADR-0035 §AF-2 envelope compliance on all dispatch results.
   - `MCPSVC-INV5`: PoR Invariant I-2 compliance for all audited actions.
