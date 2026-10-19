# Specification: AI Control Plane Model Backend Adapters Core Service

**Document ID**: SPEC-MODEL-BACKEND-ADAPTERS-SERVICE  
**Lifecycle Target**: T-03173..T-03182 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / core service)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MODEL-BACKEND-ADAPTERS  
**Status**: ACTIVE  

---

## 1. Overview & Architectural Role

The **Model Backend Adapters Core Service** (`ModelBackendService`) provides an extensible, resilient execution engine for dispatching model completion requests to diverse Large Language Model providers (Mock, OpenAI-Compatible, Anthropic, Gemini, Ollama).

It encapsulates endpoint resolution from `ModelEndpointRegistry`, request normalization, adapter lifecycle management, retry and timeout orchestration, token usage tracking (`ModelUsage`), fallback execution chains, and Proof-of-Restraint capability gating.

---

## 2. Invariants & Architectural Guarantees

| Invariant | Target | Validation Rule | Description |
| :--- | :--- | :--- | :--- |
| **`MODSERV-INV1`** | Provider Dispatch Parity | Canonical adapter per `ModelProviderType` | Every registered provider maps to a conformant adapter |
| **`MODSERV-INV2`** | Complete Token Accounting | `total == prompt + completion` | Returned usage strictly satisfies token conservation |
| **`MODSERV-INV3`** | Resilient Fallback & Error Classification | Typed error categorization | Normalized exceptions (`TIMEOUT`, `RATE_LIMIT`, `AUTH`, `UNAVAILABLE`) |
| **`MODSERV-INV4`** | Secret & Telemetry Isolation | Zero authorization header leakage | Plaintext secrets and API tokens are redacted from logs and errors |
| **`MODSERV-INV5`** | Proof-of-Restraint Invariant I-2 | Gated mutation vs. pure read query | `aios_model_complete` strictly requires capability token; health check is read-only |

---

## 3. Core Service Engine Architecture

### 3.1 Service & Adapter Interface

```python
class BaseModelAdapter(ABC):
    @abstractmethod
    async def complete(self, config: ModelEndpointConfig, request: ModelRequest) -> ModelResponse:
        """Executes completion against target backend."""
        pass

class MockModelAdapter(BaseModelAdapter):
    """Deterministic in-memory adapter for offline testing and PoR verification."""
    ...

class ModelBackendService:
    def __init__(self, registry: Optional[ModelEndpointRegistry] = None):
        self.registry = registry or ModelEndpointRegistry.default()
        self.adapters: Dict[ModelProviderType, BaseModelAdapter] = {}

    def register_adapter(self, provider: ModelProviderType, adapter: BaseModelAdapter) -> None:
        ...

    async def complete(
        self,
        request: ModelRequest,
        fallback_backends: Optional[List[str]] = None,
    ) -> ModelResponse:
        """Dispatches request to target backend with automatic fallback."""
        ...

    def health_check(self, backend_id: Optional[str] = None) -> Dict[str, Any]:
        """Read-only operational status check across endpoints."""
        ...
```

### 3.2 Standard Error Taxonomy

- `MODSERV_ERR_UNKNOWN_BACKEND`: Target backend identifier not found in registry.
- `MODSERV_ERR_TIMEOUT`: Provider request exceeded configured `timeout_ms`.
- `MODSERV_ERR_RATE_LIMIT`: Provider returned 429 rate limit error.
- `MODSERV_ERR_AUTH`: Provider authentication failure (invalid API key).
- `MODSERV_ERR_UNAVAILABLE`: Provider service unavailable (5xx or connection refused).
- `MODSERV_ERR_FALLBACK_EXHAUSTED`: Primary and all fallback backends failed.

---

## 4. Exposed FastMCP Tools

1. **`aios_model_complete`** (State-Mutating / Consequential Inference, PEP Gated):
   - **Arguments**:
     - `model_id: str`: Target backend identifier
     - `messages: List[Dict[str, Any]]`: Chat message objects
     - `temperature: float = 0.7`: Sampling temperature
     - `max_tokens: Optional[int] = None`: Token limit
     - `fallback_backends: Optional[List[str]] = None`: Fallback chain
     - `capability_token: str`: Proof-of-Restraint capability token
   - **Returns**: `ModelResponse` dictionary payload.

2. **`aios_model_service_health`** (Pure Read-Only Query):
   - **Arguments**:
     - `backend_id: Optional[str] = None`: Target backend filter
   - **Returns**: Health summary dictionary (registered endpoints, active status, adapter availability).

---

## 5. Security & Verification Strategy

- **Dual-Substrate Parity**: Scaffolded and implemented in Python (`code/aiosh-mcp/aiosh_mcp/model_backend_adapters_service.py`) and Rust (`code/aiosh-rust/aiosh-core/src/model_backend_adapters_service.rs`).
- **Comprehensive Test Suite**: Unit tests (`test_model_backend_adapters_service_unit.py`), Integration tests (`test_model_backend_adapters_service_integration.py`), Hardening tests (`test_model_backend_adapters_service_hardening.py`).
- **Proof-of-Restraint Invariant I-2**: Validated with `demo_por.py` and fastmcp token enforcement.
