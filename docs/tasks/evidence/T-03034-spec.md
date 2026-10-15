# Specification: Incident Response Runbooks Observability (T-03034)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / Observability
- **Task ID**: `T-03034`
- **Contract Reference**: `docs/tasks/evidence/T-03033-research.md`
- **Date**: 2026-10-15
- **Author**: Codebuff (Antigravity Autonomous Pair)
- **Status**: SPECIFIED — Ready for scaffold and implementation.

---

## 1. Scope & Objective

The Incident Response Runbooks Observability subsystem establishes a consolidated, read-only telemetry and health reporting fabric for incident runbook executions, NIST SP 800-61 phase progression, security diagnostic scanning budgets, policy enforcement posture, and audit trail correlation.

---

## 2. Reused vs. New Interfaces

### 2.1 Reused Interfaces
- `IncidentCategory`, `RunbookPhase`, `RunbookRiskLevel`, `RunbookTargetSubstrate`, `RunbookSpec`, `RunbookStep`, `RunbookCatalogSnapshot` (`code/aiosh-rust/aiosh-core/src/incident_runbook_data_model.rs` and `code/aiosh-mcp/aiosh_mcp/incident_runbook_data_model.py`).
- `RunbookSecurityPolicy`, `RunbookEnforcementMode`, `PolicyResultEnvelope` (`code/aiosh-rust/aiosh-core/src/incident_runbook_policy.rs` and `code/aiosh-mcp/aiosh_mcp/incident_runbook_policy.py`).
- FastMCP tool `incident_runbook` dispatch handler (`execute_runbook_action` in `code/aiosh-mcp/aiosh_mcp/incident_runbook_mcp.py`).

### 2.2 New Interfaces
- `RunbookObservabilitySnapshot`: Canonical telemetry data model.
- `RunbookObservabilityService`: Metrics aggregator and report generator.
- Action `"stats"` added to FastMCP `execute_runbook_action`.
- Constants:
  - `MAX_OBSERVABILITY_PAYLOAD_BYTES: u64 = 64 * 1024` (64 KiB cap).
  - `MAX_OBSERVABILITY_ENTRIES: usize = 128`.
  - `MAX_OBSERVABILITY_TEXT_LEN: usize = 256`.
  - `IROBS_ERR_VALIDATION: &str = "IROBS_ERR_VALIDATION"`.
  - `IROBS_ERR_INACCESSIBLE: &str = "IROBS_ERR_INACCESSIBLE"`.

---

## 3. Data Schema & Specification

### 3.1 `RunbookObservabilitySnapshot`

| Field | Type | Description |
|:---|:---|:---|
| `generated_at_utc` | `String` | RFC 3339 UTC timestamp. |
| `total_catalog_runbooks` | `usize` / `int` | Total runbooks loaded in canonical baseline catalog. |
| `total_executions` | `usize` / `int` | Total runbook execution sessions recorded. |
| `executions_by_category` | `HashMap<IncidentCategory, usize>` | Count of executions partitioned by incident category. |
| `executions_by_status` | `HashMap<String, usize>` | Count of executions by status (`active`, `completed`, `failed`, `aborted`). |
| `step_executions_by_phase` | `HashMap<RunbookPhase, usize>` | Step count partitioned by NIST SP 800-61 phase. |
| `total_ports_scanned` | `usize` / `int` | Cumulative ports scanned across diagnostic actions. |
| `total_files_scanned` | `usize` / `int` | Cumulative files inspected across file scan actions. |
| `total_web_paths_scanned` | `usize` / `int` | Cumulative HTTP endpoints probed across web actions. |
| `policy_mode` | `RunbookEnforcementMode` | Active policy mode (`enforcing`, `permissive`, `disabled`). |
| `high_risk_confirmations_total` | `usize` / `int` | Total high-risk steps requiring operator confirmation. |
| `policy_rejections_total` | `usize` / `int` | Total operations rejected by policy gates. |
| `active_sessions_count` | `usize` / `int` | Current active execution sessions. |
| `active_sessions_utilization_percent` | `f64` / `float` | Percentage of active sessions relative to `max_active_sessions`. |
| `is_healthy` | `bool` | Composite health boolean assertion. |
| `recent_audit_events_count` | `usize` / `int` | Count of runbook audit events in the recent ring tail. |

---

## 4. API Endpoints & FastMCP Action

### 4.1 FastMCP Action: `"stats"`

```python
result = execute_runbook_action(action="stats")
```
Returns:
```json
{
  "stats": {
    "generated_at_utc": "2026-10-15T14:15:00Z",
    "total_catalog_runbooks": 4,
    "total_executions": 12,
    "executions_by_category": {
      "malware": 5,
      "unauthorized_access": 4,
      "denial_of_service": 2,
      "data_exfiltration": 1
    },
    "executions_by_status": {
      "completed": 10,
      "active": 2,
      "failed": 0,
      "aborted": 0
    },
    "step_executions_by_phase": {
      "identification": 12,
      "containment": 8,
      "eradication": 6,
      "recovery": 5
    },
    "total_ports_scanned": 1500,
    "total_files_scanned": 420,
    "total_web_paths_scanned": 75,
    "policy_mode": "enforcing",
    "high_risk_confirmations_total": 8,
    "policy_rejections_total": 0,
    "active_sessions_count": 2,
    "active_sessions_utilization_percent": 2.0,
    "is_healthy": true,
    "recent_audit_events_count": 14
  }
}
```

---

## 5. Security & Invariant Analysis

1. **Proof-of-Restraint Invariant I-1**: The `"stats"` query records an audit row in `_RECORDED_MCP_CALLS` and `AuditRing`.
2. **Proof-of-Restraint Invariant I-2**: Because `"stats"` is strictly read-only and causes no state changes, capability token redemption is not required.
3. **Bounded Memory & Output Clamping**: The generated JSON output is validated against `MAX_OBSERVABILITY_PAYLOAD_BYTES` (64 KiB).
4. **Fail-Closed on Corrupted Data**: If catalog or policy data cannot be read, returns `is_healthy = false` and structured error `IROBS_ERR_INACCESSIBLE`.
