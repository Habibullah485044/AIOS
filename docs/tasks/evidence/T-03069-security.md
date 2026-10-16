# Security Review: AI Control Plane MCP Server Core Data Model (T-03069)

**Task ID**: T-03069 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / data model: Security Review)  
**Contract Reference**: `docs/tasks/evidence/T-03064-spec.md`, ADR-0035 §D-2, ADR-0037, PoR Invariant I-2  
**Date**: 2026-10-17  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: APPROVED — Comprehensive threat modeling, abuse scenario verification, and PoR Invariant I-2 audit compliance certified.

---

## 1. Attack Surface Analysis

The Model Context Protocol (MCP) Server Core data model processes external JSON-RPC 2.0 payloads received from untrusted LLMs, agents, and external orchestration scripts over stdio and network transports.

The primary attack surfaces evaluated:
1. **JSON-RPC Deserialization Boundary**: Parsing raw text into request/response objects (`from_json_str`).
2. **Identifier & Method Sanitization**: Tool names, method names, and session identifiers.
3. **Payload & Parameter Sizing**: Sizing limits on tool arguments, descriptions, and input schemas.
4. **Capability Gating & Grant Binding**: Ensuring authorization grant tokens (`grant_id`) cannot be forged or bypassed.

---

## 2. Abuse Scenarios & Mitigations

### AS-1: JSON-RPC Wire Parser Bomb / Memory Exhaustion
- **Attack Vector**: Attacker sends deeply nested or giant JSON strings (e.g. 100 MB or recursive arrays) to induce out-of-memory crashes or stack exhaustion during deserialization.
- **Mitigation (MCPDM-INV2)**: `MAX_PAYLOAD_SIZE = 10 * 1024 * 1024` (10 MiB) enforced via byte-length pre-checks prior to parsing in both Rust and Python substrates. Requests exceeding this threshold are rejected immediately with `ERR_BOUNDS_EXCEEDED (-32002)`.

### AS-2: Trojan Source / Unicode Directional Identifier Spoofing
- **Attack Vector**: Attacker injects right-to-left override codepoints (`\u202E`, `\u202B`, `\u2066..\u2069`) into tool names or session IDs (e.g. `aios.fs\u202Eread.evil`) to disguise malicious execution paths in terminal logs and audit trails.
- **Mitigation (MCPDM-INV3)**: Mandatory sanitization via `contains_bidi_or_control()` and regex `^[a-zA-Z0-9_\.\-]+$` rejects any control characters or bidirectional overrides, returning `ERR_SANITIZATION_FAILED (-32003)`.

### AS-3: Tool Argument Overrun / Parameter Smuggling
- **Attack Vector**: Attacker supplies massive argument blobs or nested malicious schemas to exhaust server memory or bypass schema validation.
- **Mitigation (MCPDM-INV2)**: Tool arguments are strictly capped at `MAX_ARGUMENTS_SIZE = 1 MiB`, descriptions at `MAX_TOOL_DESC_LEN = 1024` chars, and input schemas at `MAX_SCHEMA_SIZE = 64 KiB`. Exceeding any threshold returns `ERR_BOUNDS_EXCEEDED (-32002)`.

### AS-4: Unauthenticated Capability Hijack & Side-Channel Tool Invocation
- **Attack Vector**: Attacker attempts to invoke state-changing tools without a valid capability grant, or injects a malformed grant ID.
- **Mitigation (MCPDM-INV5 & PoR I-2)**: `McpToolCall` validates `grant_id` format (alphanumeric identifier <= 64 chars) and requires valid PEP capability verification before downstream tool execution.

---

## 3. Proof-of-Restraint (PoR) Invariant I-2 Standing Rule Verification

- **Standing Rule**: If this component adds or changes any state-changing path, confirm it cannot execute without redeeming a capability token (docs/proof-of-restraint/PLAN.md invariant I-2) and record the check in the security evidence.
- **Audit Findings**:
  - `aios_mcp_core_status` is strictly a read-only diagnostic inspection endpoint exposing protocol version and session capabilities. It mutates no system state.
  - All state-changing tool dispatches (`aios.*`) route through `_dispatch.dispatch()`, which mandates a valid cryptographic capability grant token (`grant_id`) and commits an immutable row into the SQLite WAL audit ring before execution.
  - Zero state-changing side-channels exist in the core data model.
