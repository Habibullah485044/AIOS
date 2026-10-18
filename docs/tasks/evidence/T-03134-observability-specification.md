# Specification Evidence: AI Control Plane MCP Server Core Observability (T-03134)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / observability
- **Artifact**: `docs/tasks/evidence/T-03134-observability-specification.md`
- **Spec Document**: `docs/SPEC-MCP-SERVER-CORE-OBSERVABILITY.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2

---

## 1. Specification Summary

This document establishes the contract, invariants, and data models for `McpCoreMetricsSnapshot` and `McpServerCoreObservabilityService`.

## 2. Data Contract & Model

```python
class HealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"

@dataclass(frozen=True)
class McpCoreMetricsSnapshot:
    generated_at_utc: str
    uptime_seconds: float
    total_tools_registered: int
    active_sessions_count: int
    max_sessions_capacity: int
    capacity_utilization_percent: float
    total_dispatches: int
    successful_dispatches: int
    failed_dispatches: int
    policy_denials: int
    average_dispatch_latency_ms: float
    health_status: HealthStatus
```

## 3. Invariants & Proof-of-Restraint Verification

- Strict boundary checks on capacity utilization (`[0.0, 100.0]`) and timestamps (RFC3339).
- Read-only queries guaranteed under Invariant I-2; zero capability minting or state mutation paths.
