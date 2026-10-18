# Specification: AI Control Plane Model Backend Adapters Data Model

**Document ID**: SPEC-MODEL-BACKEND-ADAPTERS  
**Lifecycle Target**: T-03163..T-03172 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / data model)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MCP-SERVER-CORE-CONFIG  
**Status**: ACTIVE  

---

## 1. Overview & Architectural Role

The **Model Backend Adapters Subsystem** provides a unified, vendor-neutral abstraction layer across diverse Large Language Model (LLM) inference providers (OpenAI-compatible APIs, Anthropic Messages API, Google Gemini GenAI, local Ollama / vLLM daemons, and deterministic offline mock adapters).

The data model establishes standard structural types and validation invariants enforced consistently across Python (`aiosh_mcp.model_backend_adapters_data_model`) and Rust (`aiosh_core::model_backend_adapters_data_model`).

---

## 2. Invariants & Architectural Guarantees

| Invariant | Target | Bounds / Validation | Description |
| :--- | :--- | :--- | :--- |
| **`MODADAPT-INV1`** | Role Canonicalization | `role in {"system", "user", "assistant", "tool"}` | Rejects non-canonical message roles fail-closed |
| **`MODADAPT-INV2`** | Token Accounting Sum | `prompt >= 0, completion >= 0, total == prompt + completion` | Strict conservation of token accounting |
| **`MODADAPT-INV3`** | Secret Isolation | `api_key_env` stores env var name, NOT plaintext key | Zero plaintext credential persistence |
| **`MODADAPT-INV4`** | Parameter Bounds | `0.0 <= temperature <= 2.0`, `1000 <= timeout_ms <= 300000` | Hard ceilings on sampling and timeouts |
| **`MODADAPT-INV5`** | PoR Invariant I-2 | Gated mutation vs. pure read query | Mutations require capability grant token |

---

## 3. Data Model Definitions

### 3.1 `ModelProviderType`
Enum representing supported inference backend architectures:
- `OPENAI_COMPATIBLE`: OpenAI, Groq, DeepSeek, Together, vLLM
- `ANTHROPIC`: Claude Messages API
- `GEMINI`: Google GenAI API
- `OLLAMA`: Local inference daemon
- `MOCK`: In-memory deterministic mock adapter

### 3.2 `ModelCapabilities`
- `streaming: bool` (default `True`)
- `tool_calling: bool` (default `True`)
- `vision: bool` (default `False`)
- `json_mode: bool` (default `True`)
- `max_context_window: int` (default `128000`)
- `max_output_tokens: int` (default `4096`)

### 3.3 `ModelEndpointConfig`
- `backend_id: str`: Identifier (e.g. `"primary-claude"`, `"local-llama3"`)
- `provider: ModelProviderType`: Provider type
- `model_name: str`: Target model identifier string
- `base_url: Optional[str]`: Optional custom HTTP endpoint base URL
- `api_key_env: Optional[str]`: Name of environment variable containing API key
- `timeout_ms: int`: Timeout in milliseconds (clamped `[1000, 300000]`)
- `max_retries: int`: Max retries on network/rate-limit error (clamped `[0, 10]`)
- `capabilities: ModelCapabilities`: Feature support flags
- `is_active: bool`: Whether endpoint is currently active

### 3.4 `ModelMessage`
- `role: str`: Canonical role (`"system"`, `"user"`, `"assistant"`, `"tool"`)
- `content: str`: Text payload
- `name: Optional[str]`: Optional participant name
- `tool_calls: Optional[List[Dict[str, Any]]]`: Tool invocation descriptors
- `tool_call_id: Optional[str]`: Result reference ID for `"tool"` responses

### 3.5 `ModelUsage`
- `prompt_tokens: int` ($>= 0$)
- `completion_tokens: int` ($>= 0$)
- `total_tokens: int` ($== \text{prompt\_tokens} + \text{completion\_tokens}$)

### 3.6 `ModelRequest`
- `model_id: str`: Target backend identifier
- `messages: List[ModelMessage]`: Conversation message history
- `temperature: float`: Sampling temperature ($0.0 \le T \le 2.0$)
- `max_tokens: Optional[int]`: Upper limit on generation
- `tools: Optional[List[Dict[str, Any]]]`: Exposed tool definitions
- `stream: bool`: Whether response should be streamed

### 3.7 `ModelResponse`
- `id: str`: Unique response identifier
- `model: str`: Generating model name
- `content: str`: Generated output content
- `tool_calls: List[Dict[str, Any]]`: Emitted tool calls
- `usage: ModelUsage`: Token accounting
- `finish_reason: str`: Termination reason (`"stop"`, `"tool_calls"`, `"length"`, `"error"`)
- `latency_ms: float`: Roundtrip duration in milliseconds

---

## 4. Exposed FastMCP Tools

1. **`aios_model_endpoint_list`** (Read-Only):
   - Arguments: None
   - Returns: List of active `ModelEndpointConfig` objects without secrets.
2. **`aios_model_endpoint_register`** (State-Changing, PEP Gated):
   - Arguments: `endpoint: Dict[str, Any]`, `capability_token: str`
   - Returns: Registration confirmation status.
