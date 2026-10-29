# Specification: AI Control Plane Model Backend Adapters Observability Subsystem

**Document ID**: SPEC-MODEL-BACKEND-ADAPTERS-OBSERVABILITY  
**Lifecycle Target**: T-03233..T-03242 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / observability)  
**Contract Reference**: ADR-0035 §AF-2, ADR-0037, OpenTelemetry GenAI Conventions, PoR Invariant I-2  
**Status**: APPROVED / ACTIVE  

---

## 1. Overview & Architectural Role

The **Model Backend Adapters Observability Subsystem** provides operational metrics collection, health state evaluation, token consumption tracking, and fallback progression telemetry for LLM providers in AIOS.

Telemetry is aggregated in-memory through `ModelBackendObservabilityService` and exposed via immutable `ModelBackendMetricsSnapshot` objects.

Parity is maintained across:
- Python Fabric: `code/aiosh-mcp/aiosh_mcp/model_backend_adapters_observability.py`
- FastMCP Production Tool: `aios_model_observability_snapshot`

---

## 2. Invariants & Wire Guarantees

| Invariant | Target | Rule | Description |
| :--- | :--- | :--- | :--- |
| **`MODOBS-INV1`** | Token Conservation | `total_tokens == prompt_tokens + completion_tokens` | Strict arithmetic equality across individual and aggregated counters. |
| **`MODOBS-INV2`** | Request Accounting | `total_requests == successful_requests + failed_requests` | Complete dispatch categorization without lost or double-counted requests. |
| **`MODOBS-INV3`** | Proof-of-Restraint (PoR Invariant I-2) | Zero tokens consumed for telemetry | Querying health status, operational metrics, or snapshots requires 0 capability tokens. |
| **`MODOBS-INV4`** | Telemetry Sanitization | Clean strings | Rejects NUL bytes, ASCII control codes (<32, 127), and zero-width unicode spaces (`\u200b`, `\ufeff`). Length clamped to 256 chars. |
| **`MODOBS-INV5`** | Health Status Determinism | Strict thresholds | `HEALTHY` (error rate < 5%), `DEGRADED` (5% <= error rate < 25% or active fallbacks), `CRITICAL` (error rate >= 25% or 0 providers healthy). |

---

## 3. Data Models & Interface Contracts

### 3.1 `HealthStatus`
```python
class HealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"
```

### 3.2 `ModelBackendMetricsSnapshot`
```python
@dataclass(frozen=True)
class ModelBackendMetricsSnapshot:
    generated_at_utc: str
    uptime_seconds: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    policy_denials: int
    fallback_triggers_count: int
    total_prompt_tokens: int
    total_completion_tokens: int
    total_tokens: int
    average_latency_ms: float
    health_status: HealthStatus
    provider_breakdown: Dict[str, int]
```

### 3.3 `ModelBackendObservabilityService`
```python
class ModelBackendObservabilityService:
    def record_completion(
        self,
        provider: str,
        duration_ms: float,
        prompt_tokens: int,
        completion_tokens: int,
        fallback_used: bool = False
    ) -> None: ...

    def record_failure(self, provider: str, error_type: str) -> None: ...

    def record_policy_denial(self) -> None: ...

    def get_snapshot(self) -> ModelBackendMetricsSnapshot: ...

    def reset(self) -> None: ...
```

---

## 4. Error Cases & Persistence Effects

1. **Error Cases**:
   - Zero requests: `average_latency_ms` safely returns `0.0` (zero-division defense).
   - Invariant violation during snapshot validation raises `ValueError` immediately.
   - Malformed timestamp or negative duration raises `ValueError`.
2. **Persistence & Audit Effects**:
   - In-memory metrics counters are transient and reset on daemon restart.
   - When snapshots are exported or inspected over MCP, an audit event (`model.observability.snapshot`) is written to `audit.db` via `AuditRing` with `outcome="ok"`.
