# Hardening Evidence: AI Control Plane Model Backend Adapters Core Service (T-03180)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / core service
- **Artifact**: `docs/tasks/evidence/T-03180-core-service-hardening.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE
- **Test Suite**: `code/aiosh-mcp/tests/test_model_backend_adapters_service_hardening.py` (3 passed)

---

## 1. Hardening & Defenses Implemented

1. **Request Message Ceiling (`MAX_REQUEST_MESSAGES = 100`)**:
   - `complete()` bounds the incoming conversation history to a ceiling of 100 messages.
   - Prevents memory consumption attacks and unbounded token serialization loops.
2. **Fallback Chain Depth Bound (`MAX_FALLBACK_DEPTH = 5`)**:
   - Bounds the total progression chain (primary backend + fallbacks) to a maximum of 5 endpoints.
   - Rejects excessively long fallback arrays that could lead to cascading network timeouts or resource amplification attacks.
3. **Fallback Deduplication & Self-Fallback Neutralization**:
   - Automatically deduplicates entries in `fallback_backends` while preserving priority order.
   - Removes redundant occurrences of the primary `model_id` within fallback lists, preventing circular dispatch loops.
4. **Secret Isolation (`redact_secrets`)**:
   - Error strings from failing backends are scrubbed of Authorization headers, `Bearer` tokens, `sk-*`, and `ghp_*` tokens prior to error propagation or audit logging.
5. **Cross-Substrate Parity**:
   - Constants `MAX_FALLBACK_DEPTH = 5`, `MAX_REQUEST_MESSAGES = 100`, and `MODSERV_ERR_INVALID_PAYLOAD` defined identically in Rust (`aiosh_core::model_backend_adapters_service`).
