# Specification: Compliance Mapping Observability (SPEC-COMPLIANCE-OBSERVABILITY)

- **Status**: SPECIFIED
- **Date**: 2026-10-11
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping Observability
- **Binding**: ADR-0035 §G-1, ADR-0037 §C-2
- **Source Code**: [`code/aiosh-rust/aiosh-core/src/compliance_observability.rs`](../code/aiosh-rust/aiosh-core/src/compliance_observability.rs)
- **Unit Tests**: [`code/aiosh-rust/aiosh-core/tests/test_compliance_observability.rs`](../code/aiosh-rust/aiosh-core/tests/test_compliance_observability.rs)
- **Integration Tests**: [`code/aiosh-rust/aiosh-core/tests/test_compliance_observability_integration.rs`](../code/aiosh-rust/aiosh-core/tests/test_compliance_observability_integration.rs)

---

## 1. Overview

The Compliance Mapping Observability subsystem provides point-in-time metrics aggregation, regulatory framework distributions, lifecycle status progression tracking, target substrate breakdown, posture scoring, capacity utilization telemetry, and audit trail correlation for the AIOS Compliance Mapping catalog.

---

## 2. Core Invariants

| Invariant | Name | Description |
|:---|:---|:---|
| `COMPOBS1` | **Temporal Format & RFC3339** | Generated timestamp `generated_at_utc` must be non-empty and conform to RFC 3339 UTC format. |
| `COMPOBS2` | **Sanitization & Length Bounds** | All metric labels and string identifiers must be stripped of control characters and capped at `MAX_TELEMETRY_TEXT_LEN` (256 characters). |
| `COMPOBS3` | **Bounded Cardinality** | Distribution maps (`mappings_by_framework`, `mappings_by_status`, `mappings_by_target_type`) must not exceed `MAX_OUTCOME_DISTRIBUTION_ENTRIES` (128 entries). |
| `COMPOBS4` | **Posture Scoring Consistency** | Monotonic compliance metrics (`compliance_percentage`, `gap_control_count`, `total_mappings`) must deterministically reflect catalog state. |
| `COMPOBS5` | **Policy Mode & System Health** | Report must reflect current policy mode (`enforcing`, `permissive`, `disabled`, `unconfigured`), capacity utilization percentage, and verify catalog health bounds (`total_mappings <= 1024`). |
| `COMPOBS6` | **Bounded Audit Tail** | Audit ring log tailing must be capped at `MAX_AUDIT_LOG_TAIL_ITEMS` (1,000 items) to prevent unbounded execution latency. |

---

## 3. Data Structures & Constants

```rust
pub const MAX_TELEMETRY_TEXT_LEN: usize = 256;
pub const MAX_OUTCOME_DISTRIBUTION_ENTRIES: usize = 128;
pub const MAX_AUDIT_LOG_TAIL_ITEMS: i64 = 1000;

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

- `COMPOBS_ERR_VALIDATION`: `"COMPOBS_ERR_VALIDATION"` — Raised when report metrics violate range, RFC3339 format, or sanitization bounds.
- `COMPOBS_ERR_SERVICE_INACCESSIBLE`: `"COMPOBS_ERR_SERVICE_INACCESSIBLE"` — Raised when the underlying compliance service or store is inaccessible.

---

## 5. API Surface

### 5.1 Rust Substrate API (`aiosh-core`)
```rust
impl ComplianceObservabilityReport {
    pub fn generate(service: &ComplianceService, ring: Option<&AuditRing>) -> Result<Self, String>;
    pub fn validate(&self) -> Result<(), String>;
}
```

### 5.2 Python MCP Tool (`aiosh-mcp`)
Surfaced via `aios.compliance` tool:
- `action: "stats"`: Returns full `ComplianceObservabilityReport` in JSON response.
- Read-only action: Emits read-only audit row to `audit_ring`; does not require capability mint/redeem token.
