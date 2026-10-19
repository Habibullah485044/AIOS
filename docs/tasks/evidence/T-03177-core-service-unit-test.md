# Unit Test Evidence: AI Control Plane Model Backend Adapters Core Service (T-03177)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / core service
- **Artifact**: `docs/tasks/evidence/T-03177-core-service-unit-test.md`
- **Test Suite**: `code/aiosh-mcp/tests/test_model_backend_adapters_service_unit.py` (5 passed)
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE

---

## 1. Invariants Certified & Test Verification

| Invariant | Test Function | Result | Certification Details |
| :--- | :--- | :--- | :--- |
| **`MODSERV-INV1`** | `test_modserv_inv1_provider_dispatch_parity` | **PASS** | Validated adapter mappings across Mock, OpenAI, Anthropic, Gemini, and Ollama |
| **`MODSERV-INV2`** | `test_modserv_inv2_token_usage_conservation` | **PASS** | Certified `total_tokens == prompt + completion` invariant; caught corrupted usage |
| **`MODSERV-INV3`** | `test_modserv_inv3_fallback_chain_error_taxonomy` | **PASS** | Certified fallback failover on timeout and `MODSERV_ERR_FALLBACK_EXHAUSTED` |
| **`MODSERV-INV4`** | `test_modserv_inv4_secret_redaction` | **PASS** | Certified Bearer keys, `sk-*`, and `ghp_*` tokens are redacted from telemetry |
| **`MODSERV-INV5`** | `test_modserv_inv5_health_check_zero_tokens` | **PASS** | Certified read-only operational query requires zero capability tokens |
