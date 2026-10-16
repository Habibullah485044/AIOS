# Security Review: AI Control Plane MCP Server Core Service (T-03079)

**Task ID**: T-03079 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / core service: Security Review)  
**Contract Reference**: `docs/tasks/evidence/T-03074-spec.md`, ADR-0035 §D-2, ADR-0037, PoR Invariant I-2  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: APPROVED — Comprehensive threat modeling, abuse scenario verification, and PoR Invariant I-2 audit compliance certified.

---

## 1. Attack Surface Analysis

The `McpServerCoreService` coordinates tool discovery, session establishment, and tool dispatch execution.

Key attack surfaces:
1. **Tool Registration & Shadowing**: Attempting to register overlapping or hijacked tools.
2. **Session Table Depletion**: Attempting to flood session registrations to exhaust memory.
3. **Privileged Tool Execution**: Attempting to invoke sensitive security or admin tools without valid capability grants.
4. **Concurrency & Race Conditions**: Multi-client concurrent tool calls or simultaneous session terminations.

---

## 2. Abuse Scenarios & Mitigations

### AS-1: Session Table Starvation (DoS)
- **Attack Vector**: Attacker floods the service with distinct session initialization requests to exhaust memory.
- **Mitigation (MCPSVC-INV2)**: Capped to `MAX_ACTIVE_SESSIONS = 64`. Terminated sessions are automatically evicted upon reaching capacity. Overflow requests fail with `MCPSVC_ERR_SESSION_CAPACITY_EXCEEDED (-32005)`.

### AS-2: Tool Catalog Shadowing & Hijacking
- **Attack Vector**: Attacker registers an existing tool name (e.g. `aios.fs.read`) to substitute malicious logic.
- **Mitigation (MCPSVC-INV1)**: Duplicate tool registration is rejected with `MCPSVC_ERR_TOOL_ALREADY_EXISTS (-32006)`. Only explicit `unregister_tool` calls by authorized controllers can remove tools.

### AS-3: Unauthenticated Privileged Dispatch
- **Attack Vector**: Attacker attempts to call administrative tools (`aios.admin.*`) without an authorization grant token (`grant_id: None`).
- **Mitigation (MCPSVC-INV3 & PoR I-2)**: Fail-closed verification rejects privileged calls missing valid grant IDs with `ERR_UNAUTHORIZED (-32001)`.

### AS-4: Concurrency Collisions & Data Races
- **Attack Vector**: Concurrent clients race to register tools or modify session state simultaneously.
- **Mitigation (MCPSVC-INV1)**: Thread-safe locking (`RwLock` in Rust, `threading.Lock` in Python) guarantees serialized writes and data race freedom.

---

## 3. Proof-of-Restraint (PoR) Invariant I-2 Standing Rule Verification

- **Standing Rule**: If this component adds or changes any state-changing path, confirm it cannot execute without redeeming a capability token (docs/proof-of-restraint/PLAN.md invariant I-2) and record the check in the security evidence.
- **Audit Findings**:
  - `aios_mcp_core_list_tools` is read-only.
  - `aios_mcp_core_dispatch` routes through `McpServerCoreService`, enforcing capability grant checks (`grant_id`) for all privileged endpoints before execution.
  - FastMCP tool invocations emit immutable audit rows to the SQLite WAL ring.
