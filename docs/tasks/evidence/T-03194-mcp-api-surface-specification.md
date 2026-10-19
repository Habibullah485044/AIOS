# Specification Evidence: AI Control Plane Model Backend Adapters MCP/API Surface (T-03194)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / MCP/API surface
- **Artifact**: `docs/tasks/evidence/T-03194-mcp-api-surface-specification.md`
- **Specification Document**: `docs/SPEC-MODEL-BACKEND-ADAPTERS-MCP-API.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, JSON-RPC 2.0, MCP Schema 2025-06-18, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE

---

## 1. Specification Overview

Task `T-03194` formalizes the interface specifications and technical invariants for the Model Backend Adapters MCP/API Surface under `SPEC-MODEL-BACKEND-ADAPTERS-MCP-API`.

### Wire Invariants Established

1. **`MODAPI-INV1` (Tool Schema Canonicalization)**: Defines tools `model_backend_list`, `model_backend_show`, `model_backend_health`, `model_backend_complete`, `model_backend_register` with formal JSON schemas.
2. **`MODAPI-INV2` (Proof-of-Restraint Gating)**: Read-only operations cost zero tokens; `model_backend_complete` and `model_backend_register` strictly require `capability_token`, returning `-32003` (`ERR_UNAUTHORIZED`) fail-closed.
3. **`MODAPI-INV3` (Standardized Result Envelopes)**: Structured result payloads `{status, ok, data/response/registered, error}`.
4. **`MODAPI-INV4` (Secret & Telemetry Redaction)**: Automatic sanitization via `redact_secrets()`.
5. **`MODAPI-INV5` (Fallback & Execution Safety)**: Bounds fallback chains to 5, timeouts to `[1000, 300000]` ms, and prompt payloads to 1 MiB.

---

## 2. Verification

- Authored specification document `docs/SPEC-MODEL-BACKEND-ADAPTERS-MCP-API.md`.
- Validated with `tools/check_evidence.py`.
