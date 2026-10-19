# Security Review: AI Control Plane Model Backend Adapters MCP/API Surface (T-03199)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / MCP/API surface
- **Task ID**: `T-03199`
- **Specification Document**: `docs/SPEC-MODEL-BACKEND-ADAPTERS-MCP-API.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE

---

## 1. Threat Modeling & Abuse Scenarios

| ID | Threat Vector | CWE | Attack Surface | Mitigation & Enforcement | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **AS-01** | Capability Token Bypass / Mutation Escalation | CWE-285 | `model_backend_complete`, `model_backend_register` | PoR Invariant I-2 gating: pure read operations (`list`, `show`, `health`, `ping`) consume 0 tokens; state-mutating actions (`complete`, `register`) strictly require `capability_token`. Missing/empty/whitespace token returns JSON-RPC error code `-32003` (`ERR_UNAUTHORIZED`) fail-closed. | MITIGATED |
| **AS-02** | Credential & Telemetry Leakage in JSON-RPC Responses | CWE-532, CWE-200 | JSON-RPC result/error envelopes, FastMCP tool responses | Invariant `MODAPI-INV4`: `redact_secrets()` sanitizes Bearer tokens, OpenAI keys (`sk-[a-zA-Z0-9_-]{10,}`), GitHub PATs (`ghp_*`), and sensitive environmental credentials before output serialization. | MITIGATED |
| **AS-03** | Fallback Exhaustion & Cascading Loop Flooding | CWE-400 | `model_backend_complete` `fallbacks` param | Invariant `MODAPI-INV5`: Fallback chain deduplicated and strictly capped at `MAX_FALLBACK_DEPTH = 5`. Prevents recursive cascades or circular dispatch across model endpoints. | MITIGATED |
| **AS-04** | JSON-RPC Method Injection / Unknown Method Spoofing | CWE-20, CWE-1286 | JSON-RPC 2.0 `method` dispatch | `handle_request()` strictly whitelists supported methods (`model_backend_list`, `model_backend_show`, `model_backend_health`, `model_backend_complete`, `model_backend_register`), returning standard error `-32601` (`Method not found`) on any unknown or malformed method. | MITIGATED |
| **AS-05** | Denial of Service via Payload Flooding | CWE-400 | `prompt` parameter in `complete` | Message payloads bounded by `MAX_MESSAGE_BYTES = 1 MiB`, timeout bounded to `[1000ms, 300000ms]`, rejecting oversized payloads with error `-32602` (`ERR_INVALID_PARAMS`). | MITIGATED |
| **AS-06** | Path Traversal / Identifier Spoofing in Backend IDs | CWE-22, CWE-20 | `backend_id` parameter | Positional backend identifier checked against regex whitelist `[a-zA-Z0-9_\-\.]`, length bounded to 64 chars, rejecting directory traversal (`..`, `/`, `\`) with error `-32602`. | MITIGATED |

---

## 2. Proof-of-Restraint (PoR) Conformance Verification

- **Invariant I-2 (Redeem-Before-Act)**:
  - Read-only operations (`model_backend_list`, `model_backend_show`, `model_backend_health`) require and consume zero tokens.
  - Consequential inference (`model_backend_complete`) and registry modification (`model_backend_register`) fail closed before any adapter dispatch if an explicit capability token is not provided.
  - Unit and integration test suites (`test_por_token_gating_pure_reads`, `test_por_token_gating_mutations_rejected`, `test_integration_e2e_api_lifecycle`) verify all bypass attempts fail closed with `-32003`.

---

## 3. Hardening Recommendations for T-03200

1. **Max Length & Identifier Validation in API Layer**: Add explicit check for `backend_id` format and length (<= 64 chars) directly in `handle_show`, `handle_health`, `handle_complete`, and `handle_register`.
2. **Temperature Clamping**: Ensure `temperature` is strictly within `[0.0, 2.0]` at the API parameter validation layer, returning `-32602` if out of bounds.
3. **Structured Audit Row Correlation**: Correlate incoming JSON-RPC `id` with the emitted audit event or response envelope.
4. **Rust Core Parity**: Mirror all validation boundaries and parameter checks in `aiosh-core::model_backend_adapters_api`.

---

## 4. Verification

- All 25 Python test suite cases pass in `code/aiosh-mcp/tests`.
- Rust compilation and checks in `aiosh-core` pass with zero errors.
- Evidence validated with `tools/check_evidence.py`.
