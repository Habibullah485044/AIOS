# Specification: Incident Response Runbooks Observability Subsystem (SPEC-INCIDENT-RUNBOOK-OBSERVABILITY)

- **Status**: SHIPPED
- **Date**: 2026-10-15
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Incident Response Runbooks / observability
- **Binding**: NIST SP 800-61 Rev. 2, CISA Playbooks, ADR-0035 §AF-2, Proof-of-Restraint (PoR) Invariant I-2
- **Shipped Implementations**:
  - Rust Core Substrate: `code/aiosh-rust/aiosh-core/src/incident_runbook_observability.rs`
  - Python MCP Fabric: `code/aiosh-mcp/aiosh_mcp/incident_runbook_observability.py`
  - FastMCP Tool Surface: `code/aiosh-mcp/aiosh_mcp/incident_runbook_mcp.py` (`action="stats"`)
- **Evidence Trail**:
  - Research: [T-03033-observability-research.md](tasks/evidence/T-03033-observability-research.md)
  - Specification: [T-03034-spec.md](tasks/evidence/T-03034-spec.md)
  - Scaffold: [T-03035-observability-scaffold.md](tasks/evidence/T-03035-observability-scaffold.md)
  - Implementation: [T-03036-observability-implementation.md](tasks/evidence/T-03036-observability-implementation.md)
  - Unit Tests: [T-03037-observability-unit.md](tasks/evidence/T-03037-observability-unit.md)
  - Integration: [T-03038-observability-integration.md](tasks/evidence/T-03038-observability-integration.md)
  - Security Review: [T-03039-observability-security-review.md](tasks/evidence/T-03039-observability-security-review.md)
  - Hardening: [T-03040-observability-hardening.md](tasks/evidence/T-03040-observability-hardening.md)

---

## 1. Subsystem Architecture

The Incident Response Runbooks Observability subsystem aggregates real-time point-in-time metrics, execution state counters, phase progression distribution, diagnostic scan budgets, and policy compliance posture across the AIOS runtime.

```
       +---------------------------------------------+
       | FastMCP Tool Surface: `aios_runbook(stats)` |
       +---------------------------------------------+
                              |
       +---------------------------------------------+
       |   RunbookObservabilityService (Rust/Python) |
       +---------------------------------------------+
           |                    |                 |
+---------------------+ +---------------+ +-------------------------+
| Catalog Progression | | State Counter | | Safe Envelope & Audit   |
| (Category / Phases) | | (Utilization) | | (ADR-0035 §AF-2 Honest) |
+---------------------+ +---------------+ +-------------------------+
```

---

## 2. Snapshot Data Model (`RunbookObservabilitySnapshot`)

| Field | Type | Description |
|:---|:---|:---|
| `generated_at_utc` | `String` (ISO 8601) | Timestamp of metrics collection in UTC. |
| `total_catalog_runbooks` | `usize` / `int` | Count of registered baseline and tenant runbook specifications. |
| `total_executions` | `usize` / `int` | Cumulative active and baseline execution instances. |
| `executions_by_category` | `dict[str, int]` | Distribution across NIST incident categories. |
| `executions_by_status` | `dict[str, int]` | State breakdown: `active`, `completed`, `failed`, `aborted`. |
| `step_executions_by_phase` | `dict[str, int]` | Step count breakdown across phases (containment, eradication, etc.). |
| `total_ports_scanned` | `usize` / `int` | Cumulative ports probed across network security scans. |
| `total_files_scanned` | `usize` / `int` | Cumulative files inspected via RustSec file scans. |
| `total_web_paths_scanned` | `usize` / `int` | Cumulative HTTP paths evaluated via web scans. |
| `policy_mode` | `RunbookEnforcementMode` | Active policy mode: `enforcing`, `permissive`, or `disabled`. |
| `high_risk_confirmations_total`| `usize` / `int` | Invariant I-2 confirmation tokens verified. |
| `policy_rejections_total` | `usize` / `int` | Security policy gate blocks. |
| `active_sessions_count` | `usize` / `int` | Active sessions running concurrently. |
| `active_sessions_utilization_percent` | `f64` / `float` | Capacity utilization vs `max_active_sessions`. |
| `is_healthy` | `bool` | Capacity and operational health indicator. |
| `recent_audit_events_count` | `usize` / `int` | Audit log rows committed during recording window. |

---

## 3. Observability Result Envelope & Safety Invariants

To guarantee that failure modes are never silent and never cause process crash loops, all snapshot queries return an `ObservabilityResultEnvelope`:

```rust
pub struct ObservabilityResultEnvelope {
    pub ok: bool,
    pub snapshot: Option<RunbookObservabilitySnapshot>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub audit_row_required: bool,
}
```

### Safety & Fault-Tolerance Invariants:
1. **Never Silent Failure**: Any corruption or out-of-bounds metrics returns an explicit `IROBS_ERR_VALIDATION` error with `audit_row_required = true`.
2. **Honest Audit on Over-Capacity (ADR-0035 §AF-2)**: When `active_sessions_count > max_active_sessions`, the service does not abort; it computes the actual utilization (e.g. $160.0\%$), sets `is_healthy = false`, and flags `audit_row_required = true` to record an honest audit trail.
3. **No Temp Leaks**: Atomic persistence (`save_snapshot_atomic`) writes to `{path}.tmp.{pid}` and removes the temporary file on any error path.

---

## 4. Bounded Resource Limits

| Limit Constant | Value | Enforcement Scope |
|:---|:---:|:---|
| `MAX_OBSERVABILITY_PAYLOAD_BYTES` | `64 KiB` (65,536 bytes) | Max serialized JSON snapshot size. |
| `MAX_OBSERVABILITY_ENTRIES` | `128` entries | Max distinct keys in maps (categories, statuses, phases). |
| `MAX_OBSERVABILITY_TEXT_LEN` | `256` chars | Max length of string attributes (e.g. `generated_at_utc`). |
| `MAX_OBSERVABILITY_ACTIVE_SESSIONS` | `100,000` | Hard sanity cap on active sessions iterator. |
| Utilization range | $[0.0, 10000.0]\%$ | Finite float bounds check. |

---

## 5. Copy-Pasteable Usage Examples

### 5.1 Invoking via FastMCP CLI

```bash
python -m aiosh_mcp.incident_runbook_mcp --action stats
```

Example JSON response:
```json
{
  "ok": true,
  "action": "stats",
  "audit_row_required": false,
  "stats": {
    "generated_at_utc": "2026-10-15T14:30:00Z",
    "total_catalog_runbooks": 2,
    "total_executions": 2,
    "executions_by_category": {
      "malware_containment": 1,
      "unauthorized_access": 1
    },
    "executions_by_status": {
      "active": 0,
      "completed": 0,
      "failed": 0,
      "aborted": 0
    },
    "step_executions_by_phase": {
      "containment": 2,
      "post_incident": 2
    },
    "policy_mode": "enforcing",
    "active_sessions_count": 0,
    "active_sessions_utilization_percent": 0.0,
    "is_healthy": true
  }
}
```

### 5.2 Python Substrate Usage

```python
from aiosh_mcp.incident_runbook_observability import RunbookObservabilityService

envelope = RunbookObservabilityService.generate_snapshot_safe()
if envelope.ok:
    print(f"Observability Healthy: {envelope.snapshot.is_healthy}")
    print(f"Total Runbooks: {envelope.snapshot.total_catalog_runbooks}")
else:
    print(f"Error [{envelope.error_code}]: {envelope.error_message}")
```

### 5.3 Rust Substrate Usage

```rust
use aiosh_core::incident_runbook_data_model::RunbookCatalogSnapshot;
use aiosh_core::incident_runbook_observability::RunbookObservabilityService;
use aiosh_core::incident_runbook_policy::RunbookSecurityPolicy;

let catalog = RunbookCatalogSnapshot::canonical_baseline();
let policy = RunbookSecurityPolicy::default();
let envelope = RunbookObservabilityService::generate_snapshot_safe(&catalog, &policy, 2);

if envelope.ok {
    let snap = envelope.snapshot.unwrap();
    println!("Catalog runbooks: {}", snap.total_catalog_runbooks);
}
```

---

## 6. Constraints and Known Limitations

1. **Ephemeral State Persistence**: Observability metrics reflect live session memory. Process restarts reset active counter tallies to 0 unless exported via `save_snapshot_atomic()`.
2. **Cardinality Caps**: Breakdown maps are constrained to 128 keys to prevent adversarial exhaustion of audit memory during multi-vector cluster incidents.
3. **Local Scope**: Active session counters monitor the local daemon instance; distributed multi-node fleet aggregation relies on upstream telemetry consumers.
