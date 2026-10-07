# Research Evidence: T-02842 — redeem-before-act gate: Research

## Task Information
- **Task ID**: `T-02842`
- **Subsystem**: `Phase 2 — Security Kernel & PEP Fabric / Proof of Restraint / redeem-before-act gate`
- **Title**: `redeem-before-act gate: Research`
- **Status**: Completed

## 1. Facts vs. Assumptions

### Facts (Verified from Codebase)
1. **MCP Dispatch Architecture**:
   - `code/aiosh-mcp/aiosh_mcp/server.py` exposes tools over FastMCP (`aios_fs_read`, `aios_process_list`, `aios_audit_*`, `pentest_*`).
   - Every tool routes through `aiosh_mcp._dispatch.dispatch()` for classification and PEP grant checking.
   - Currently, `_dispatch.py` invokes `audit_client.grant_check(conn, grant_id, tool, target)`.
   - `audit_client.grant_check()` validates grant existence, expiry timestamp, and glob scope matching, but does **not** check `single_use` or `redeemed_at`.
2. **TypeScript Agent Loop**:
   - `code/aiosh-cli/src/agent.ts` does not execute host tools directly; all host actions route over stdio to `aiosh_mcp.server`.
   - The Python server is the authoritative PEP dispatch boundary.
3. **Existing Capability Model**:
   - In Component 1 (T-02835), `code/aiosh-cli/src/pep.ts` added `single_use`, `redeemed_at`, and `PepGrantManager.redeem()`.
   - However, Python's `audit_client.py` does not yet possess a `grant_redeem()` method, and `_dispatch.py` does not redeem grants prior to tool dispatch.
4. **Current Invariant Violation**:
   - Because `_dispatch.py` never marks grants as redeemed or emits `pep.capability.redeem` rows, an agent with a single grant can invoke consequential tools (`pentest.nmap`, `fs.write`) an infinite number of times within the grant's TTL window.
   - This violates Invariant I-2 ("A consequential tool must be unreachable unless a redeem row is committed first").

### Assumptions Tested & Clarified
- *Assumption*: Tools could bypass the PEP gate via direct CLI execution.
  *Fact*: CLI pentest and tool commands invoke `PepGrantManager.check()` and `AuditRing.write()`. By integrating `redeem()` directly into the dispatch pipeline, all execution paths are unified.

## 2. Dispatch Paths Enumeration
We enumerated every execution path in AIOS that can trigger a state-changing or consequential tool:

| Path | Source File | Authority Boundary | Current Behavior | Required Gate |
|---|---|---|---|---|
| **MCP Server Dispatch** | `code/aiosh-mcp/aiosh_mcp/server.py` & `_dispatch.py` | Authoritative | Calls `grant_check()`, runs tool, calls `commit()` | Must atomically call `grant_redeem()` before tool execution |
| **Agent Loop Dispatch** | `code/aiosh-cli/src/agent.ts` | Preflight | Calls MCP via stdio bridge | Inherits MCP authoritative gate |
| **CLI Direct Execution** | `code/aiosh-cli/src/cli.ts` | Authoritative | Calls `PepGrantManager.check()` | Must invoke `PepGrantManager.redeem()` before tool process spawn |
| **Rust Core Kernel** | `code/aiosh-rust/aiosh-core/src/pep_grant*.rs` | Authoritative | Scope verification | Must verify single-use flag and `redeemed_at` status |

## 3. Decisions Needed for Specification (T-02843)
1. **Gate Placement in Python MCP**:
   - Should `grant_redeem()` occur inside `dispatch()` or inside `_recorded_call()`?
   - *Decision*: `dispatch()` must perform the atomic redemption if `require_grant` is true or if a consequential tool is invoked with a single-use grant. This prevents any tool wrapper from forgetting to redeem.
2. **Read-Only vs Consequential Tools**:
   - Read-only tools (`aios.audit.tail`, `aios.process.list`) that do not require grants should not consume capability tokens unless an explicit grant was provided for audit attribution.
   - Irreversible / consequential tools (`pentest.*`, `fs.write`, `reboot`, etc.) must strictly require an unredeemed grant.
3. **Failure Semantics**:
   - If redemption fails (already redeemed, expired, or concurrent double-spend), dispatch immediately returns `ok: False`, emits a refusal audit row with detail `"capability token already redeemed at ..."`, and refuses to invoke the tool function.
