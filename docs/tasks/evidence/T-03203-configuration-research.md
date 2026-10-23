# Research Evidence: AI Control Plane Model Backend Adapters Configuration (T-03203)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / configuration
- **Artifact**: `docs/tasks/evidence/T-03203-configuration-research.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2

---

## 1. Context & Objectives

The Model Backend Adapters subsystem requires a robust, declarative configuration schema allowing operators and autonomous agents to:
1. Configure model endpoints, provider types, and authentication credentials securely.
2. Specify fallback provider priority chains and failover timeouts.
3. Configure rate-limiting parameters (requests per minute, burst windows).
4. Maintain strict secret isolation and redaction (OpenAI `sk-*`, Anthropic `sk-ant-*`, Gemini API keys, Bearer tokens).
5. Support immutable runtime snapshots and dynamic configuration reload without restarting the host daemon.

## 2. Authoritative Facts vs Assumptions

### Facts (Empirically Verified in Codebase)
- `code/aiosh-mcp/aiosh_mcp/model_backend_adapters_data_model.py` defines `ModelEndpointConfig` and `ModelEndpointRegistry`.
- `MIN_TIMEOUT_MS = 1000`, `MAX_TIMEOUT_MS = 300000`, and `MAX_FALLBACK_DEPTH = 5` are architectural constants.
- Proof-of-Restraint Invariant I-2 mandates that mutating operations require explicit capability tokens.
- `redact_secrets` in `model_backend_adapters_service.py` strips sensitive tokens using regex matching.

### Assumptions to Validate
- Configuration files will be stored in JSON/YAML format under `.aios/config/model_backends.json` or specified via environment variable `AIOSH_MODEL_CONFIG`.
- Hot reloading can be triggered via `reload()` without interrupting in-flight requests.

## 3. Decisions & Unknowns

- **Decision 1**: Configuration will be represented by immutable `ModelBackendConfig` dataclass instances.
- **Decision 2**: Default configuration will provide a zero-credential `mock` provider for offline deterministic testing.
- **Decision 3**: Environmental overrides will follow standard hierarchical convention (`AIOSH_MODEL_DEFAULT_PROVIDER`, `AIOSH_MODEL_TIMEOUT_MS`).
