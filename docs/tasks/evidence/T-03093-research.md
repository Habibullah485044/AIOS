# Research Document: AI Control Plane MCP Server Core MCP/API Surface (T-03093)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / MCP/API surface
- **Focus**: JSON-RPC 2.0 Transport, FastMCP API Adapters, Tool Registration & Dispatch Wire Protocol, Capability Token Validation, and Audit Ring Emission
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, ADR-0037, JSON-RPC 2.0 Specification, PoR Invariant I-2
- **Author**: Codebuff (Antigravity Autonomous Pair)
- **Date**: 2026-10-18

---

## 1. Executive Summary & Objective

The **MCP Server Core MCP/API Surface** provides the standardized wire protocol and programmatic API endpoints allowing external AI models, IDE agents, and local supervisory controllers to interact with AIOS tools, prompts, and resources.

This research establishes facts, constraints, security threat models, and architectural boundaries for exposing the core service engine (`McpServerCoreService`) through the MCP protocol wire format (`tools/list`, `tools/call`, `initialize`, `ping`).

---

## 2. Facts vs. Assumptions

### 2.1 Authoritative Facts
1. **Protocol Pinned**: ADR-0035 §D-2 binds the project to the Model Context Protocol (MCP) as the single tool-call protocol AIOS exposes to external models. The schema version is pinned at `2025-06-18`.
2. **Transport Layer**: Stdio transport is the primary local communication channel for MCP client/server pairs (`FastMCP("aiosh-mcp")`).
3. **Execution Gating**: Per ADR-0035 §AF-2 and Sprint 2 requirements, every tool call must execute through the policy enforcement point (`dispatch_mod.dispatch()` -> classifier -> PEP) prior to invocation.
4. **Audit Immutability**: Every consequential or state-changing call must write exactly one immutable audit row into `audit.db` via `AuditRing`.
5. **Restraint Invariant**: Under Proof-of-Restraint (PoR Invariant I-2), any state-changing or administrative call (`aios.admin.*`) cannot execute without redeeming a capability token (`--grant`).
6. **Data Model Bounds**: `MAX_ARGUMENTS_SIZE` is capped at 1 MiB (1,048,576 bytes); tool count is capped at `MAX_TOOLS_COUNT = 256`; sessions are capped at `MAX_ACTIVE_SESSIONS = 64`.

### 2.2 Assumptions Validated
1. **Substrate Coexistence**: Python FastMCP server (`aiosh-mcp`) handles direct JSON-RPC stdio transports for host LLM clients, while Rust core (`aiosh-core`) provides the underlying deterministic data structures and local daemon dispatch.
2. **Error Envelope**: All errors returned across the MCP API wire must conform to JSON-RPC 2.0 error specifications (`code`, `message`, optional `data`).

---

## 3. Security Audit & Threat Modeling (AC-1..AC-5)

A comprehensive security audit of the MCP/API surface reveals critical threat vectors that must be mitigated by design:

1. **SA-1 (Unauthenticated Parameter Injection)**:
   - *Risk*: Malicious JSON payloads with nested prototypes, arbitrary large payloads, or unescaped NUL bytes attempting to exploit deserialization.
   - *Audit Control*: Strict JSON schema validation; strict byte ceiling of 1 MiB (`MAX_ARGUMENTS_SIZE`); immediate rejection on embedded NUL bytes.
2. **SA-2 (Capability Escalation & Bypass)**:
   - *Risk*: Agent invoking administrative tools (`aios.admin.*`, `aios.audit.rotate`) without holding an authentic PEP grant token.
   - *Audit Control*: Strict gating via PEP validator prior to dispatch execution; refusal rows committed to audit log upon missing/invalid grant tokens.
3. **SA-3 (Denial of Service via Session Saturation)**:
   - *Risk*: Rogue client flooding `initialize` requests to exhaust memory and session IDs.
   - *Audit Control*: Active session cap of 64 (`MAX_ACTIVE_SESSIONS`), automatic eviction of terminated sessions, and heartbeat timeout enforcement.
4. **SA-4 (Timing & Hang Attacks via Unbounded Tool Execution)**:
   - *Risk*: Tool execution hanging indefinitely or blocking the server event loop.
   - *Audit Control*: Hard-clamped execution timeouts in `[1, 300]` seconds (default 30 seconds); asynchronous cancellation support.
5. **SA-5 (Silent Failures / Missing Audit Trail)**:
   - *Risk*: Tool execution fails or rejects without leaving an auditable footprint.
   - *Audit Control*: ADR-0035 fail-open/fail-closed auditing mandate — even failed or rejected invocations write an honest audit record.

---

## 4. Key Unknowns and Architectural Decisions Needed

1. **Decision D-1 (Tool Discovery Granularity)**:
   - *Resolution*: `tools/list` returns the full tool catalog with input schemas, while respecting filter tags if requested.
2. **Decision D-2 (Error Code Mapping)**:
   - *Resolution*: Map standard JSON-RPC codes (`-32700` Parse Error, `-32600` Invalid Request, `-32601` Method Not Found, `-32602` Invalid Params, `-32603` Internal Error) and custom AIOS codes (`-32001` Bounds Exceeded, `-32002` Unauthorized).
3. **Decision D-3 (Parity Across Runtimes)**:
   - *Resolution*: Ensure Python `aiosh-mcp` and Rust `aiosh-core` share identical JSON structures and error definitions for all MCP wire transactions.

---

## 5. Citations & References
- Model Context Protocol Specification: `https://spec.modelcontextprotocol.io/` (2025-06-18)
- JSON-RPC 2.0 Specification: `https://www.jsonrpc.org/specification`
- AIOS Architecture Decision Records: `ADR-0035` (AI Control Plane), `ADR-0036` (Retention Ring), `ADR-0037` (Dispatch Gate)
- Proof of Restraint: `docs/proof-of-restraint/PLAN.md` Invariant I-2
