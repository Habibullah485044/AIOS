# Security Review: AI Control Plane MCP Server Core MCP/API Surface (T-03099)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / MCP/API surface
- **Focus**: Threat Modeling, Abuse Scenarios, Proof-of-Restraint Invariant I-2 Verification, and Audit Invariants
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2
- **Author**: Codebuff (Antigravity Autonomous Pair)
- **Date**: 2026-10-18

---

## 1. Executive Summary

This security review formally evaluates the threat posture of the Model Context Protocol (MCP) wire API layer across Python (`aiosh_mcp.mcp_server_core_api`) and Rust (`aiosh_core::mcp_server_core_api`).

No open bypasses, unauthenticated privileged executions, or unhandled exceptions remain open. All state-changing pathways enforce Proof-of-Restraint capability token verification and cryptographic audit logging.

---

## 2. Abuse Scenarios & Mitigations

| Scenario ID | Attack Vector / Misuse Attempt | Evaluated Component | Mitigation & Invariant | Status |
| :--- | :--- | :--- | :--- | :--- |
| **AS-1** | Parameter Injection / NUL-byte injection in tool names or argument keys | `handle_tools_call` | Proactive NUL byte scan across UTF-8 tokens; returns `ERR_INVALID_PARAMS` (-32602) | **SECURED** |
| **AS-2** | Memory Exhaustion DoS via oversized JSON-RPC request bodies | `handle_tools_call` | `MAX_ARGUMENTS_SIZE = 1 MiB` strict clamp; returns `ERR_BOUNDS_EXCEEDED` (-32001) | **SECURED** |
| **AS-3** | Capability Token Bypass on administrative tools (`aios.admin.*`) | PEP Dispatch & API handler | Strict PoR Invariant I-2 gating; missing grant returns `ERR_UNAUTHORIZED` (-32002) | **SECURED** |
| **AS-4** | Malformed / Recursive JSON crash exploit | `handle_raw_message` | Safely caught with standard JSON-RPC `-32700` Parse Error | **SECURED** |
| **AS-5** | Audit evasion on failed or rejected calls | Server dispatch pipeline | ADR-0035 audit mandate: refusal rows emitted with reason to `audit.db` | **SECURED** |

---

## 3. Proof-of-Restraint (PoR) Conformance Check

- **Requirement (PoR Invariant I-2)**: No state-changing or administrative tool call can execute without redeeming an authentic capability grant token (`--grant` / `grant_id`).
- **Audit Verification**:
  1. `aios.admin.restart` called with `grant: null` -> REJECTED with code `-32002` (`ERR_UNAUTHORIZED`).
  2. `aios.admin.restart` called with valid `grant: "token"` -> ALLOWED.
  3. All unauthorized attempts trigger failure logging.

---

## 4. Verification Conclusion

The MCP/API surface is secure against injection, resource exhaustion, and privilege escalation. Ready for Hardening (T-03100).
