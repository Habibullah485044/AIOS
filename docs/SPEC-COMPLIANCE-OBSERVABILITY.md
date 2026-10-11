# Specification: Compliance Mapping Observability (SPEC-COMPLIANCE-OBSERVABILITY)

- **Status**: IMPLEMENTED & VERIFIED
- **Date**: 2026-10-11
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping Observability
- **Binding**: ADR-0035 §G-1, ADR-0037 §C-2
- **Source Code**:
  - Rust substrate: [`code/aiosh-rust/aiosh-core/src/compliance_observability.rs`](../code/aiosh-rust/aiosh-core/src/compliance_observability.rs)
  - Python MCP substrate: [`code/aiosh-mcp/aiosh_mcp/compliance_observability.py`](../code/aiosh-mcp/aiosh_mcp/compliance_observability.py)
  - MCP Tool Handler: [`code/aiosh-mcp/aiosh_mcp/server.py`](../code/aiosh-mcp/aiosh_mcp/server.py)
- **Unit Tests**:
  - Rust: [`code/aiosh-rust/aiosh-core/tests/test_compliance_observability_unit.rs`](../code/aiosh-rust/aiosh-core/tests/test_compliance_observability_unit.rs)
  - Python: [`code/aiosh-mcp/tests/test_compliance_observability_unit.py`](../code/aiosh-mcp/tests/test_compliance_observability_unit.py)
- **Integration Tests**:
  - Rust: [`code/aiosh-rust/aiosh-core/tests/test_compliance_observability_integration.rs`](../code/aiosh-rust/aiosh-core/tests/test_compliance_observability_integration.rs)
  - Python: [`code/aiosh-mcp/tests/test_compliance_observability_integration.py`](../code/aiosh-mcp/tests/test_compliance_observability_integration.py)

---

## 1. Overview

The Compliance Mapping Observability subsystem provides point-in-time metrics aggregation, regulatory framework distributions, lifecycle status progression tracking, target substrate breakdown, posture scoring, capacity utilization telemetry, and audit trail correlation for the AIOS Compliance Mapping catalog.

---

## 2. Core Invariants

| Invariant | Name | Description |
|:---|:---|:---|
| `COMPOBS1` | **Temporal Format & RFC3339** | Generated timestamp `generated_at_utc` must be non-empty and conform to RFC 3339 UTC format. |
| `COMPOBS2` | **Sanitization & Length Bounds** | All metric labels and string identifiers must be stripped of control characters, zero-width spaces, and capped at `MAX_TELEMETRY_TEXT_LEN` (256 characters). |
| `COMPOBS3` | **Bounded Cardinality** | Distribution maps (`mappings_by_framework`, `mappings_by_status`, `mappings_by_target_type`) must not exceed `MAX_OUTCOME_DISTRIBUTION_ENTRIES` (128 entries). |
| `COMPOBS4` | **Posture Scoring Consistency** | Monotonic compliance metrics (`compliance_percentage`, `gap_control_count`, `total_mappings`) must deterministically reflect catalog state; percentage must be a finite float $0.0 \le p \le 100.0$ and never NaN. |
| `COMPOBS5` | **Policy Mode & System Health** | Report must reflect current policy mode (`enforcing`, `permissive`, `disabled`, `unconfigured`), capacity utilization percentage, and verify catalog health bounds (`total_mappings <= 1024`). |
| `COMPOBS6` | **Bounded Audit Tail** | Audit ring log tailing must be capped at `MAX_AUDIT_LOG_TAIL_ITEMS` (1,000 items) to prevent unbounded execution latency. |

---

## 3. Data Structures & Constants

```rust
pub const MAX_TELEMETRY_TEXT_LEN: usize = 256;
pub const MAX_OUTCOME_DISTRIBUTION_ENTRIES: usize = 128;
pub const MAX_AUDIT_LOG_TAIL_ITEMS: i64 = 1000;
pub const MAX_COMPLIANCE_ENTRIES_CAPACITY: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComplianceObservabilityReport {
    pub generated_at_utc: String,
    pub total_mappings: usize,
    pub mappings_by_framework: HashMap<String, usize>,
    pub mappings_by_status: HashMap<String, usize>,
    pub mappings_by_target_type: HashMap<String, usize>,
    pub compliance_percentage: f64,
    pub gap_control_count: usize,
    pub policy_mode: String,
    pub capacity_utilization_percent: u8,
    pub is_healthy: bool,
    pub recent_audit_events_count: usize,
}
```

---

## 4. Error Constants

- `COMPOBS_ERR_VALIDATION`: `"COMPOBS_ERR_VALIDATION"` — Raised when report metrics violate range, RFC3339 format, zero-width characters, or sanitization bounds.
- `COMPOBS_ERR_SERVICE_INACCESSIBLE`: `"COMPOBS_ERR_SERVICE_INACCESSIBLE"` — Raised when the underlying compliance service or store is inaccessible.

---

## 5. Usage & Invocation Examples

### 5.1 Rust Substrate
```rust
use aiosh_core::compliance_service::ComplianceService;
use aiosh_core::audit::AuditRing;

let service = ComplianceService::with_canonical_baseline();
let ring = AuditRing::open_in_memory().ok();

let report = service.observability_report(ring.as_ref()).expect("observability report");
println!("Compliance: {:.1}% across {} controls", report.compliance_percentage, report.total_mappings);
```

### 5.2 Python MCP JSON-RPC Surface
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "aios_compliance",
    "arguments": { "action": "stats" }
  }
}
```

Response:
```json
{
  "ok": true,
  "action": "stats",
  "report": {
    "generated_at_utc": "2026-10-11T09:30:00+00:00",
    "total_mappings": 4,
    "mappings_by_framework": {
      "nist_sp_800_53_rev5": 2,
      "soc2_type2": 1,
      "cis_controls_v8": 1
    },
    "mappings_by_status": { "compliant": 4 },
    "mappings_by_target_type": { "pep_gate": 3, "audit_ring": 1 },
    "compliance_percentage": 100.0,
    "gap_control_count": 0,
    "policy_mode": "unconfigured",
    "capacity_utilization_percent": 0,
    "is_healthy": true,
    "recent_audit_events_count": 0
  },
  "audit_id": 1
}
```

---

## 6. Constraints & Known Limitations (Honest)

1. **Point-in-Time Only**: Reports calculate the immediate snapshot state and do not store temporal history or time-series metrics. Historical auditing is delegated to the `AuditRing` WAL.
2. **Cardinality Ceilings**: Distribution maps are bounded to at most 128 distinct entries (`MAX_OUTCOME_DISTRIBUTION_ENTRIES = 128`).
3. **Audit Tail Horizon**: The audit event correlator inspects at most the last 1,000 log records (`MAX_AUDIT_LOG_TAIL_ITEMS = 1000`) to guarantee $O(1)$ constant latency.
4. **Read-Only Non-Mutating**: The `stats` action performs zero write operations and does not require capability minting / token redemption (conforms to Proof-of-Restraint Invariant I-2).

---

## 7. Evidence & History

- Research: [`docs/tasks/evidence/T-02933-research.md`](tasks/evidence/T-02933-research.md)
- Specification: [`docs/tasks/evidence/T-02934-spec.md`](tasks/evidence/T-02934-spec.md)
- Scaffold: [`docs/tasks/evidence/T-02935-scaffold.md`](tasks/evidence/T-02935-scaffold.md)
- Implementation: [`docs/tasks/evidence/T-02936-impl.md`](tasks/evidence/T-02936-impl.md)
- Unit Testing: [`docs/tasks/evidence/T-02937-unit.md`](tasks/evidence/T-02937-unit.md)
- Integration: [`docs/tasks/evidence/T-02938-integration.md`](tasks/evidence/T-02938-integration.md)
- Security Review: [`docs/tasks/evidence/T-02939-security.md`](tasks/evidence/T-02939-security.md)
- Hardening: [`docs/tasks/evidence/T-02940-hardening.md`](tasks/evidence/T-02940-hardening.md)
- Documentation: [`docs/tasks/evidence/T-02941-doc.md`](tasks/evidence/T-02941-doc.md)
