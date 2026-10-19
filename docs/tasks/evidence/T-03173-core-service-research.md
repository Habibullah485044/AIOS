# Research Evidence: AI Control Plane Model Backend Adapters Core Service (T-03173)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / core service
- **Artifact**: `docs/tasks/evidence/T-03173-core-service-research.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS

---

## 1. Context & Architectural Requirements

1. **Role of Core Service**:
   The Model Backend Adapters Core Service provides execution orchestration, provider adapter dispatch, fallback routing, and telemetry capture for AI model inference requests across AIOS control planes.
2. **Provider Abstraction**:
   Must support dispatching across `ModelProviderType`:
   - `Mock`: In-memory deterministic completions for hermetic CI, offline runs, and PoR verification.
   - `OpenAICompatible`: Standard `v1/chat/completions` API protocol.
   - `Anthropic`: Claude Messages API protocol (`/v1/messages`).
   - `Gemini`: Google GenAI API protocol (`/v1beta/models/{model}:generateContent`).
   - `Ollama`: Local daemon protocol (`/api/chat`).
3. **Resilience & Fallback Strategy**:
   - Configurable timeout handling and retry with exponential backoff on transient errors (`429`, `503`).
   - Fallback chain progression: If a primary endpoint fails, fail over to a designated fallback endpoint (e.g. cloud provider -> local Ollama or fallback replica).
4. **Security & Proof of Restraint Invariants**:
   - `MODSERV-INV1`: Provider dispatch parity across supported provider schemas.
   - `MODSERV-INV2`: Token usage conservation (`total_tokens == prompt_tokens + completion_tokens`).
   - `MODSERV-INV3`: Error classification and fail-closed timeout/error semantics.
   - `MODSERV-INV4`: Secret isolation and header redaction in all telemetry and logs.
   - `MODSERV-INV5`: PoR Invariant I-2 compliance: `aios_model_complete` requires a capability token grant; read-only health checks require zero tokens.

---

## 2. Decision Log

- **Decision 1**: Implement `ModelBackendService` in Python (`aiosh_mcp.model_backend_adapters_service`) with full async support and deterministic mock adapter, alongside dual Rust types in `aiosh_core::model_backend_adapters_service`.
- **Decision 2**: Integrate `aios_model_complete` and `aios_model_service_health` into FastMCP `server.py`.
- **Decision 3**: Standardize error types: `MODSERV_ERR_UNKNOWN_BACKEND`, `MODSERV_ERR_TIMEOUT`, `MODSERV_ERR_RATE_LIMIT`, `MODSERV_ERR_AUTH`, `MODSERV_ERR_UNAVAILABLE`.
