# Specification: AI Control Plane Model Backend Adapters MCP/API Surface

**Document ID**: SPEC-MODEL-BACKEND-ADAPTERS-MCP-API  
**Lifecycle Target**: T-03193..T-03202 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / MCP/API surface)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §AF-2, JSON-RPC 2.0, MCP Schema 2025-06-18, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS-SERVICE  
**Status**: ACTIVE  

---

## 1. Overview & Architectural Role

The **Model Backend Adapters MCP/API Surface** provides a standardized Model Context Protocol (MCP) wire interface exposing model backend catalog exploration, endpoint inspection, runtime health monitoring, resilient completion dispatch with multi-stage fallback, and dynamic endpoint registration.

Both the Python runtime (`aiosh_mcp.model_backend_adapters_api`) and the Rust runtime (`aiosh_core::model_backend_adapters_api`) implement this specification to guarantee cross-substrate behavioral parity and strict compliance with Proof-of-Restraint (PoR) Invariant I-2.

---

## 2. Invariants & Wire Guarantees

| Invariant | Target | Validation Rule | Description |
| :--- | :--- | :--- | :--- |
| **`MODAPI-INV1`** | Tool Schema Canonicalization | Tools: `model_backend_list`, `model_backend_show`, `model_backend_health`, `model_backend_complete`, `model_backend_register` | Strict JSON schema definitions with NUL rejection and bounds checking |
| **`MODAPI-INV2`** | Proof-of-Restraint Invariant I-2 Gating | Pure read operations consume 0 tokens. Mutations require `capability_token` | Missing/empty token returns JSON-RPC error `-32003` (`ERR_UNAUTHORIZED`) fail-closed |
| **`MODAPI-INV3`** | Standardized Result Envelopes | Deterministic `{status, ok, data, error}` payload | Strict envelope consistency across success and error conditions |
| **`MODAPI-INV4`** | Secret & Telemetry Redaction | Never expose raw API keys or tokens in wire outputs | Sanitizes Bearer tokens, `sk-*`, and `ghp_*` with `[REDACTED_SECRET]` |
| **`MODAPI-INV5`** | Fallback & Execution Safety | Fallback depth bounded at 5, message count bounded at 100, timeouts in `[1000, 300000]` ms | Prevents recursion, denial-of-service, or hanging requests |

---

## 3. Tool Reference & Signatures

### 3.1 `model_backend_list` (Read-Only)
- **Description**: Enumerate registered model backend endpoints.
- **PoR Token Requirement**: 0 tokens.
- **Parameters**:
  - `provider` (string, optional): Filter by provider (`mock`, `openai_compatible`, `anthropic`, `gemini`, `ollama`).
  - `active_only` (boolean, optional, default: false): Only return active endpoints.
- **Result Schema**: `{status: "success", ok: true, count: int, endpoints: List[Dict]}`.

### 3.2 `model_backend_show` (Read-Only)
- **Description**: Inspect endpoint configuration, capabilities, and timeout limits.
- **PoR Token Requirement**: 0 tokens.
- **Parameters**:
  - `backend_id` (string, required): Target endpoint identifier (max 64 chars, traversal-free).
- **Result Schema**: `{status: "success", ok: true, endpoint: Dict}`.

### 3.3 `model_backend_health` (Read-Only)
- **Description**: Inspect runtime operational readiness and adapter loading status.
- **PoR Token Requirement**: 0 tokens.
- **Parameters**:
  - `backend_id` (string, optional): Specific endpoint identifier to check.
- **Result Schema**: `{status: "success", ok: true, data: Dict}`.

### 3.4 `model_backend_complete` (State-Mutating / Consequential Inference)
- **Description**: Execute completion inference through target backend with fallback progression.
- **PoR Token Requirement**: Valid PEP capability token required (`capability_token`).
- **Parameters**:
  - `backend_id` (string, required): Primary backend identifier.
  - `prompt` (string, required): Input prompt text (max 1 MiB).
  - `temperature` (float, optional, default: 0.7): Sampling temperature in `[0.0, 2.0]`.
  - `fallbacks` (array of strings, optional, max: 5): Ordered fallback backend identifiers.
  - `capability_token` (string, required): Proof-of-Restraint capability grant token.
- **Result Schema**: `{status: "success", ok: true, response: Dict}`.

### 3.5 `model_backend_register` (State-Mutating Endpoint Modification)
- **Description**: Register or update an inference backend endpoint in the registry.
- **PoR Token Requirement**: Valid PEP capability token required (`capability_token`).
- **Parameters**:
  - `backend_id` (string, required): Unique identifier for endpoint (1..64 chars).
  - `provider` (string, required): Provider adapter type.
  - `model_name` (string, required): Underlying model identifier.
  - `base_url` (string, optional): Base API URL starting with `http://` or `https://`.
  - `api_key_env` (string, optional): Environment variable name holding credentials.
  - `timeout_ms` (integer, optional, default: 30000): Timeout in milliseconds `[1000, 300000]`.
  - `capability_token` (string, required): Proof-of-Restraint capability grant token.
- **Result Schema**: `{status: "success", ok: true, registered: Dict}`.

---

## 4. Error Code Taxonomy

| Code | Constant | Meaning |
| :--- | :--- | :--- |
| `0` | `ERR_SUCCESS` | Execution successful |
| `-32602` | `ERR_INVALID_PARAMS` | Invalid parameter, bounds violation, missing required field, NUL byte |
| `-32003` | `ERR_UNAUTHORIZED` | Missing or invalid capability token for state-mutating tool |
| `-32004` | `ERR_NOT_FOUND` | Specified backend_id not found in registry |
| `-32005` | `ERR_TIMEOUT` | Upstream provider request exceeded configured timeout |
| `-32603` | `ERR_INTERNAL` | Unhandled internal exception |

---

## 5. Usage & Wire Invocation Examples

### 5.1 Enumerate Model Backends (Pure Read)
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "model_backend_list",
  "params": {
    "provider": "mock",
    "active_only": true
  }
}
```

**Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "status": "success",
    "ok": true,
    "count": 1,
    "endpoints": [
      {
        "backend_id": "mock-default",
        "provider": "mock",
        "model_name": "mock-model-v1",
        "is_active": true
      }
    ]
  }
}
```

### 5.2 Execute Model Inference with Fallback (Gated Mutation)
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "model_backend_complete",
  "params": {
    "backend_id": "mock-default",
    "prompt": "Evaluate system security posture",
    "temperature": 0.5,
    "fallbacks": ["secondary-backend"],
    "capability_token": "grant-cap-token-883"
  }
}
```

### 5.3 Register Dynamic Endpoint (Gated Mutation)
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "model_backend_register",
  "params": {
    "backend_id": "custom-openai",
    "provider": "openai_compatible",
    "model_name": "gpt-4o",
    "base_url": "https://api.openai.com/v1",
    "api_key_env": "OPENAI_API_KEY",
    "timeout_ms": 30000,
    "capability_token": "grant-cap-token-884"
  }
}
```

---

## 6. Constraints & Known Limitations

1. **Proof-of-Restraint Gating**:
   - `model_backend_complete` and `model_backend_register` strictly require a valid capability token. Missing or whitespace tokens fail-closed immediately with `-32003`.
2. **Payload Size Caps**:
   - Prompt content is strictly bounded at 1 MiB (`1024 * 1024` bytes) and NUL bytes (`\0`) are prohibited.
3. **Fallback Depth**:
   - Chained fallbacks are clamped to at most 5 alternative endpoints to avoid cascading latencies.
4. **Identifier Formatting**:
   - Backend identifiers must be between 1 and 64 characters, and cannot contain path traversal (`..`, `/`, `\`) or ASCII control characters.
5. **Streaming Primitive**:
   - In accordance with ADR-0035 §5, token streaming is deferred to future sprint milestones; completions return atomic responses.

---

## 7. Evidence & Implementation References

- Research Evidence: [docs/tasks/evidence/T-03193-mcp-api-surface-research.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03193-mcp-api-surface-research.md)
- Specification Evidence: [docs/tasks/evidence/T-03194-mcp-api-surface-specification.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03194-mcp-api-surface-specification.md)
- Scaffold Evidence: [docs/tasks/evidence/T-03195-mcp-api-surface-scaffold.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03195-mcp-api-surface-scaffold.md)
- Implementation Evidence: [docs/tasks/evidence/T-03196-mcp-api-surface-implementation.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03196-mcp-api-surface-implementation.md)
- Unit Test Evidence: [docs/tasks/evidence/T-03197-mcp-api-surface-unit-test.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03197-mcp-api-surface-unit-test.md)
- Integration Evidence: [docs/tasks/evidence/T-03198-mcp-api-surface-integration.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03198-mcp-api-surface-integration.md)
- Security Review Evidence: [docs/tasks/evidence/T-03199-mcp-api-surface-security-review.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03199-mcp-api-surface-security-review.md)
- Hardening Evidence: [docs/tasks/evidence/T-03200-mcp-api-surface-hardening.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03200-mcp-api-surface-hardening.md)
- Documentation Evidence: [docs/tasks/evidence/T-03201-mcp-api-surface-documentation.md](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03201-mcp-api-surface-documentation.md)

