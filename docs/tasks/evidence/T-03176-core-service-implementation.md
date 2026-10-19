# Implementation Evidence: AI Control Plane Model Backend Adapters Core Service (T-03176)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / core service
- **Artifact**: `docs/tasks/evidence/T-03176-core-service-implementation.md`
- **Implementation File**: `code/aiosh-mcp/aiosh_mcp/model_backend_adapters_service.py`
- **Test Suite**: `code/aiosh-mcp/tests/test_model_backend_adapters_service_impl.py` (4 passed)
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE

---

## 1. Implementation Highlights

1. **Provider Adapters**:
   - `MockModelAdapter`: Deterministic in-memory response, latency simulation, configurable error modes.
   - `OpenAICompatibleAdapter`: Formats OpenAI `/v1/chat/completions` request schema and extracts token usage.
   - `AnthropicAdapter`: Separates system prompt messages from user/assistant chat history for Claude Messages API.
   - `GeminiAdapter`: Conforms to Google GenAI API request format and token telemetry.
   - `OllamaAdapter`: Formats payloads for local Ollama `/api/chat` daemon.
2. **Fallback Orchestration (`MODSERV-INV3`)**:
   - `ModelBackendService.complete()` iterates through `[request.model_id, *fallback_backends]`.
   - On error or inactive status, seamlessly falls over to next candidate in the chain.
   - If all backends fail, raises `MODSERV_ERR_FALLBACK_EXHAUSTED`.
3. **Usage Accounting Invariant (`MODSERV-INV2`)**:
   - `response.usage.validate_invariants()` is enforced on every returned response (`total == prompt + completion`).
4. **Secret Redaction (`MODSERV-INV4`)**:
   - `redact_secrets()` sanitizes error messages and logs, stripping API keys (`sk-*`, `ghp_*`, Bearer tokens).
