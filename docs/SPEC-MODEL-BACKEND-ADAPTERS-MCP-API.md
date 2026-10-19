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
