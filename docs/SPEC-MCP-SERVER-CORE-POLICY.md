# Specification: AI Control Plane MCP Server Core Security Policy Subsystem

**Document ID**: SPEC-MCP-SERVER-CORE-POLICY  
**Lifecycle Target**: T-03123..T-03132 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / security policy)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §F-2, PoR Invariant I-2  
**Status**: ACTIVE  

---

## 1. Overview & Architectural Role

The **MCP Server Core Security Policy Subsystem** implements Policy Enforcement Point (PEP) gating and policy evaluation rules for all MCP tool calls and resource accesses within AIOS.

Both Python (`aiosh_mcp.mcp_server_core_policy`) and Rust (`aiosh_core::mcp_server_core_policy`) implement this specification with byte-level schema parity.

---

## 2. Policy Invariants & Contracts

| Invariant | Identifier | Type / Scope | Default / Bound | Description |
| :--- | :--- | :--- | :--- | :--- |
| **POL-INV1** | `rule_id` | `String` | Non-empty, $\le 64$ chars | Unique policy rule identifier |
| **POL-INV2** | `role` | `String` | `*`, `agent:read-only`, `agent:operator`, `admin` | Subject role targeting |
| **POL-INV3** | `tool_pattern` | `String` | Glob or exact match | Matching tool names (e.g. `aios_mcp_*`) |
| **POL-INV4** | `action` | `PolicyAction` | `read_only`, `diagnostics`, `state_changing`, `administrative` | Tool action category classification |
| **POL-INV5** | `effect` | `PolicyEffect` | `ALLOW`, `DENY`, `REQUIRE_CAPABILITY` | Policy rule outcome |
| **POL-INV6** | `priority` | `i32` | `0..1000` | Evaluation priority (higher takes precedence) |
| **POL-INV7** | `max_rules` | `usize` | `256` | Maximum active rules in policy catalog |
| **POL-INV8** | Invariant I-2 | Core Rule | Strict gating | State-changing and admin actions require valid capability token |

---

## 3. Evaluation Semantics

1. **Resolution Hierarchy**:
   - Rules matched by `role` and `tool_pattern`.
   - Highest `priority` rule executes.
   - If multiple rules match with identical priority, `DENY` takes precedence over `ALLOW`.
2. **Default Fallback**:
   - Read-only queries default to `ALLOW` for authenticated agents.
   - Consequential or state-changing tools default to `REQUIRE_CAPABILITY`.
   - Administrative tools without matching `admin` role or valid token default to `DENY`.
3. **Audit Emission**:
   - Every evaluated request generates an auditable record `mcp.policy.evaluate` capturing `subject`, `tool`, `effect`, and `rule_id`.
