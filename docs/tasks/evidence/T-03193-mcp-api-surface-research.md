# Research Evidence: AI Control Plane Model Backend Adapters MCP/API Surface (T-03193)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / MCP/API surface
- **Task ID**: `T-03193`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, JSON-RPC 2.0, MCP Schema 2025-06-18, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE

---

## 1. Executive Summary & Architectural Role

The **Model Backend Adapters MCP/API Surface** exposes the model backend routing, health querying, fallback orchestration, and dynamic registration mechanisms to external LLMs, agent subagents, and supervisory controllers over the Model Context Protocol (MCP) wire format.

This research grounds the MCP API surface in authoritative architecture documents, performs a rigorous pre-implementation security audit, and delineates the technical invariants and wire tools required for the MCP endpoint suite.

---

## 2. Facts vs. Assumptions

### 2.1 Authoritative Facts
1. **MCP Protocol Binding (ADR-0035 §D-2)**: The system exposes tool execution over FastMCP stdio/JSON-RPC 2.0 pinned to MCP Schema `2025-06-18`.
2. **Proof-of-Restraint Invariant I-2 Gating**: Read-only wire tools (`model_backend_list`, `model_backend_show`, `model_backend_health`) consume 0 capability tokens; inference completion (`model_backend_complete`) and dynamic endpoint registration (`model_backend_register`) require a validated PEP capability token in the payload (`capability_token`), failing closed with error code `-32003` (`ERR_UNAUTHORIZED`) if missing or invalid.
3. **Dual-Substrate Wire Parity**: Both Python (`aiosh_mcp.model_backend_adapters_api`) and Rust (`aiosh_core::model_backend_adapters_api`) expose canonical JSON serialization and identical error envelopes.
4. **Bounds Enforcement**: Arguments bounded by `MAX_ARGUMENTS_SIZE = 1 MiB`, messages bounded by `MAX_REQUEST_MESSAGES = 100`, fallback chains bounded by `MAX_FALLBACK_DEPTH = 5`.

### 2.2 Validated Assumptions
1. Wire tools integrate directly with `ModelBackendService` and `ModelEndpointRegistry` created in T-03173..T-03182.
2. FastMCP registers tools using `@mcp.tool()` or programmatic tool registration function `register_model_backend_mcp_tools(mcp_server)`.

---

## 3. Security Audit & Threat Modeling (SA-1..SA-5)

| ID | Threat Vector | CWE | Attack Surface | Mitigation & Enforcement | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SA-1** | Unauthenticated Inference & Token Theft | CWE-285 | `model_backend_complete` | PEP capability token gating: `capability_token` is verified before dispatch. Unauthenticated calls reject immediately with `-32003` (`UNAUTHORIZED`). | MITIGATED |
| **SA-2** | Credential Exfiltration via Error Payloads | CWE-200, CWE-532 | JSON-RPC error responses | Wire responses and error payloads pass through `redact_secrets()`, purging Bearer tokens, `sk-*`, and `ghp_*` patterns before wire transmission. | MITIGATED |
| **SA-3** | Denial of Service via Cascading Fallback Loops | CWE-400 | `model_backend_complete` with cyclic fallbacks | Fallback chains deduplicated and strictly capped at 5 endpoints; circular fallbacks eliminated. | MITIGATED |
| **SA-4** | Malicious Parameter Deserialization | CWE-116, CWE-1286 | Tool argument vectors | Rejection of NUL bytes (`\0`), traversal sequences (`..`), and oversized strings (> 64 chars for backend IDs). | MITIGATED |
| **SA-5** | Execution Hangs via Unresponsive Providers | CWE-400 | Remote provider HTTP calls | Timeouts clamped to `[1000, 300000]` ms with asyncio timeout wrappers. | MITIGATED |

---

## 4. Architectural Decisions

- **D-1 (Tool Naming Convention)**: Standardized prefix `model_backend_*` (`model_backend_list`, `model_backend_show`, `model_backend_health`, `model_backend_complete`, `model_backend_register`).
- **D-2 (Response Envelope)**: Structured dictionary conforming to standard `{status: "success"|"error", ok: bool, data: ..., error: ...}`.
- **D-3 (Dual Substrate Exports)**: Implement both Python FastMCP helper functions and Rust JSON-RPC handler functions.
