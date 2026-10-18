# Unit Test Evidence: AI Control Plane MCP Server Core Observability (T-03137)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / observability
- **Artifact**: `docs/tasks/evidence/T-03137-observability-unit-test.md`
- **Unit Test File**: `code/aiosh-mcp/tests/test_mcp_server_core_observability_unit.py`

---

## 1. Test Battery Coverage

1. **Invariants Validation (`test_unit_observability_invariants_validation`)**:
   - Asserts non-empty RFC3339 timestamp enforcement.
   - Asserts mathematical consistency (`total == successful + failed`).
   - Asserts capacity utilization bounds (`[0.0, 100.0]`).
2. **Health Status State Transitions (`test_unit_health_status_transitions`)**:
   - Validates `HEALTHY` under standard operation.
   - Validates transition to `DEGRADED` when capacity $\ge 85\%$ or failure rate $\ge 5\%$.
   - Validates transition to `CRITICAL` when capacity $\ge 98\%$ or failure rate $\ge 20\%$.
3. **Metrics Aggregation Precision (`test_unit_metrics_aggregation_accuracy`)**:
   - Asserts exact counting of dispatches, successes, failures, and average latency calculation.

---

## 2. Test Execution Output

```
code/aiosh-mcp/tests/test_mcp_server_core_observability_unit.py ... [100%]
============================== 3 passed in 0.58s ==============================
```
