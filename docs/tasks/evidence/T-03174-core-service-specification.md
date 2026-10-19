# Specification Evidence: AI Control Plane Model Backend Adapters Core Service (T-03174)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / core service
- **Artifact**: `docs/tasks/evidence/T-03174-core-service-specification.md`
- **Specification Document**: [docs/SPEC-MODEL-BACKEND-ADAPTERS-SERVICE.md](../../docs/SPEC-MODEL-BACKEND-ADAPTERS-SERVICE.md)
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS

---

## 1. Specification Deliverables Summary

1. **Architecture & Scope**:
   - Specified `ModelBackendService` as the unified dispatch and orchestration engine for AI model completions across diverse providers.
   - Defined `BaseModelAdapter` interface and pluggable adapters for Mock, OpenAI-Compatible, Anthropic, Gemini, and Ollama providers.
2. **Invariants Defined**:
   - `MODSERV-INV1`: Provider dispatch parity across supported schemas.
   - `MODSERV-INV2`: Token usage conservation (`total_tokens == prompt_tokens + completion_tokens`).
   - `MODSERV-INV3`: Resilient fallback chains and standard error taxonomy (`UNKNOWN_BACKEND`, `TIMEOUT`, `RATE_LIMIT`, `AUTH`, `UNAVAILABLE`, `FALLBACK_EXHAUSTED`).
   - `MODSERV-INV4`: Secret and telemetry isolation (zero plaintext key or header leakage).
   - `MODSERV-INV5`: PoR Invariant I-2 gating: `aios_model_complete` requires a capability token grant; `aios_model_service_health` is pure read-only.
3. **Exposed Tool Contracts**:
   - Specified JSON-RPC tool contracts and argument structures for `aios_model_complete` and `aios_model_service_health`.
4. **Cross-Substrate Requirements**:
   - Established dual Python (`aiosh_mcp.model_backend_adapters_service`) and Rust (`aiosh_core::model_backend_adapters_service`) parity.
