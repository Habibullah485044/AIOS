# Specification: AI Control Plane Model Backend Adapters Observability Subsystem

**Document ID**: SPEC-MODEL-BACKEND-ADAPTERS-OBSERVABILITY  
**Lifecycle Target**: T-03233..T-03242 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / observability)  
**Contract Reference**: ADR-0035 §AF-2, ADR-0035 §F-2, ADR-0037, OpenTelemetry GenAI Conventions, PoR Invariant I-2  
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

## 4. Copy-Pasteable Usage Examples

### 4.1 Python Programmatic Inspection
```python
from aiosh_mcp.model_backend_adapters_observability import get_global_observability_service

service = get_global_observability_service()
snapshot = service.get_snapshot()

print(f"Health Status: {snapshot.health_status.value}")
print(f"Total Requests: {snapshot.total_requests}")
print(f"Total Tokens: {snapshot.total_tokens}")
print(f"Average Latency: {snapshot.average_latency_ms} ms")
```

### 4.2 MCP Wire Invocation (`aios_model_observability_snapshot`)
```json
{
  "jsonrpc": "2.0",
  "id": "obs-req-01",
  "method": "tools/call",
  "params": {
    "name": "aios_model_observability_snapshot",
    "arguments": {}
  }
}
```

Response:
```json
{
  "jsonrpc": "2.0",
  "id": "obs-req-01",
  "result": {
    "status": "success",
    "ok": true,
    "data": {
      "generated_at_utc": "2026-10-29T22:20:00.000000+00:00",
      "uptime_seconds": 124.50,
      "total_requests": 15,
      "successful_requests": 15,
      "failed_requests": 0,
      "policy_denials": 0,
      "fallback_triggers_count": 0,
      "total_prompt_tokens": 1200,
      "total_completion_tokens": 600,
      "total_tokens": 1800,
      "average_latency_ms": 142.305,
      "health_status": "HEALTHY",
      "provider_breakdown": {
        "mock": 10,
        "gemini": 5
      }
    }
  }
}
```

---

## 5. Constraints & Known Limitations Honestly Stated

1. **In-Memory Volatility**: Point-in-time metrics counters reset upon daemon restart. Durable history is reconstructed from `audit.db` SQLite rows.
2. **Provider Key Ceiling**: Distinct provider tracking is capped at `MAX_TRACKED_PROVIDERS = 64`. Any excess distinct names are aggregated under `"other"`.
3. **Duration Bounds**: Single-request duration telemetry is capped at `MAX_DURATION_MS = 3,600,000.0` ms (1 hour). Negative values normalize to 0.0.
4. **Token Addition Bounds**: Token additions are clamped to `[0, 10,000,000]`. Negative numbers normalize to 0.
5. **Zero Token Requirement**: Operational telemetry queries require 0 capability tokens under PoR Invariant I-2.

---

## 6. Lifecycle Evidence Links

- **T-03233 (Research)**: [`docs/tasks/evidence/T-03233-observability-research.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03233-observability-research.md)
- **T-03234 (Specification)**: [`docs/tasks/evidence/T-03234-observability-specification.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03234-observability-specification.md)
- **T-03235 (Scaffold)**: [`docs/tasks/evidence/T-03235-observability-scaffold.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03235-observability-scaffold.md)
- **T-03236 (Implementation)**: [`docs/tasks/evidence/T-03236-observability-implementation.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03236-observability-implementation.md)
- **T-03237 (Unit Test)**: [`docs/tasks/evidence/T-03237-observability-unit-test.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03237-observability-unit-test.md)
- **T-03238 (Integration)**: [`docs/tasks/evidence/T-03238-observability-integration.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03238-observability-integration.md)
- **T-03239 (Security Review)**: [`docs/tasks/evidence/T-03239-observability-security-review.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03239-observability-security-review.md)
- **T-03240 (Hardening)**: [`docs/tasks/evidence/T-03240-observability-hardening.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03240-observability-hardening.md)
- **T-03241 (Documentation)**: [`docs/tasks/evidence/T-03241-observability-documentation.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/tasks/evidence/T-03241-observability-documentation.md)
