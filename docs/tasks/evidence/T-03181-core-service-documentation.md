# Documentation Evidence: AI Control Plane Model Backend Adapters Core Service (T-03181)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / core service
- **Artifact**: `docs/tasks/evidence/T-03181-core-service-documentation.md`
- **Updated Documentation**: `code/aiosh-mcp/README.md`
- **Specification Reference**: [docs/SPEC-MODEL-BACKEND-ADAPTERS-SERVICE.md](../../docs/SPEC-MODEL-BACKEND-ADAPTERS-SERVICE.md)

---

## 1. Documentation Updates Summary

1. **Subsystem Architecture & Role**:
   - Documented the role of `ModelBackendService`: unified dispatch engine across provider adapters (Mock, OpenAI, Anthropic, Gemini, Ollama), fallback progression, and usage tracking.
2. **Invariants & Guarantees**:
   - Outlined `MODSERV-INV1` (provider dispatch parity), `MODSERV-INV2` (token usage conservation), `MODSERV-INV3` (resilient fallback & error classification), `MODSERV-INV4` (secret isolation & redaction), and `MODSERV-INV5` (Proof-of-Restraint Invariant I-2 capability token gating).
3. **Tool Invocation Examples**:
   - Provided JSON-RPC 2.0 payloads for `aios_model_complete` (consequential mutation, requires capability token) and `aios_model_service_health` (pure read-only, 0 tokens).
4. **Constraints & Security Hardening**:
   - Documented request message ceilings (`MAX_REQUEST_MESSAGES = 100`), fallback chain depth clamp (`MAX_FALLBACK_DEPTH = 5`), fallback deduplication, and secret masking in error chains.
5. **Traceability**:
   - Linked all lifecycle evidence artifacts (T-03173 through T-03181) to ensure full auditability.
