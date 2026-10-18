# Specification Evidence: AI Control Plane Model Backend Adapters Data Model (T-03164)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / data model
- **Artifact**: `docs/tasks/evidence/T-03164-data-model-specification.md`
- **Specification Document**: [docs/SPEC-MODEL-BACKEND-ADAPTERS.md](../../SPEC-MODEL-BACKEND-ADAPTERS.md)
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2

---

## 1. Specification Summary

1. **Contracts Defined**:
   - `ModelProviderType`: Enum for `OPENAI_COMPATIBLE`, `ANTHROPIC`, `GEMINI`, `OLLAMA`, and `MOCK`.
   - `ModelCapabilities`: Struct capturing streaming, tool calling, vision, context window, and token ceilings.
   - `ModelEndpointConfig`: Configuration for backend endpoints, referencing `api_key_env` to guarantee secret isolation.
   - `ModelMessage`: Canonical message structure with mandatory role validation (`system`, `user`, `assistant`, `tool`).
   - `ModelUsage`: Token accounting with non-negativity and sum invariants (`total == prompt + completion`).
   - `ModelRequest` and `ModelResponse`: Canonical request and response envelopes.
2. **Invariants Formalized (`MODADAPT-INV1..MODADAPT-INV5`)**:
   - `MODADAPT-INV1`: Role canonicalization.
   - `MODADAPT-INV2`: Token accounting sum conservation.
   - `MODADAPT-INV3`: Zero plaintext credentials (`api_key_env` only).
   - `MODADAPT-INV4`: Strict parameter bounds (`temperature: [0.0, 2.0]`, `timeout_ms: [1000, 300000]`).
   - `MODADAPT-INV5`: PoR Invariant I-2 gating: pure read operations require zero tokens; mutations strictly require capability token redemption.
3. **Cross-Substrate Parity**:
   - Concrete schemas aligned between Python dataclasses and Rust Serde structs.
