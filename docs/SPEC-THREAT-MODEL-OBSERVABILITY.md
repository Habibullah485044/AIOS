# Specification: Threat Model Observability (SPEC-THREAT-MODEL-OBSERVABILITY)

- **Status**: DRAFT (Task T-02772)
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Observability
- **Binding**: ADR-0035 §G-1, ADR-0036 §C-2

## 1. Overview
The Threat Model Observability subsystem provides point-in-time metrics aggregation, STRIDE category distributions, severity distributions, lifecycle status progression tracking, risk exposure scoring, and audit trail correlation for the AIOS Threat Model Maintenance catalog.

## 2. Core Invariants

| Invariant | Name | Description |
|:---|:---|:---|
| `THREATOBS1` | **Temporal Format & RFC3339** | Generated timestamp `generated_at_utc` must be non-empty and conform to RFC3339 UTC format. |
| `THREATOBS2` | **Sanitization & Length Bounds** | All metric labels and keys must be stripped of control characters and capped at `MAX_TELEMETRY_TEXT_LEN` (256 characters). |
| `THREATOBS3` | **Bounded Cardinality** | Distribution maps (`threats_by_category`, `threats_by_severity`, `threats_by_status`) must not exceed `MAX_OUTCOME_DISTRIBUTION_ENTRIES` (128 entries). |
| `THREATOBS4` | **Risk Exposure Integrity** | Monotonic risk metrics (`critical_unmitigated_count`, `overall_risk_score`) must match underlying catalog evaluation. |
| `THREATOBS5` | **Policy Mode & System Health** | Report must reflect current policy mode (`enforcing`, `permissive`, `disabled`) and verify catalog health bounds. |
| `THREATOBS6` | **Bounded Audit Tail** | Audit ring log tailing must be capped at `MAX_AUDIT_LOG_TAIL_ITEMS` (1,000 items) to prevent execution unbounded overhead. |

## 3. Data Structures

```rust
pub const MAX_TELEMETRY_TEXT_LEN: usize = 256;
pub const MAX_OUTCOME_DISTRIBUTION_ENTRIES: usize = 128;
pub const MAX_AUDIT_LOG_TAIL_ITEMS: i64 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatModelObservabilityReport {
    pub generated_at_utc: String,
    pub total_threats: usize,
    pub threats_by_category: HashMap<String, usize>,
    pub threats_by_severity: HashMap<String, usize>,
    pub threats_by_status: HashMap<String, usize>,
    pub critical_unmitigated_count: usize,
    pub overall_risk_score: u32,
    pub policy_mode: String,
    pub is_healthy: bool,
    pub recent_audit_events_count: usize,
}
```

## 4. Error Constants

- `THREATOBS_ERR_VALIDATION`: "THREATOBS_ERR_VALIDATION" — Raised when report metrics violate range, RFC3339 timestamp format, or sanitization limits.
- `THREATOBS_ERR_SERVICE_INACCESSIBLE`: "THREATOBS_ERR_SERVICE_INACCESSIBLE" — Raised when the underlying threat catalog or service is inaccessible.

## 5. Rust API

```rust
impl ThreatModelObservabilityReport {
    pub fn generate(service: &ThreatModelService, ring: Option<&AuditRing>) -> Result<Self, String>;
    pub fn validate(&self) -> Result<(), String>;
}
```

## 6. MCP Surface
Surfaced via `aios.threat.metrics`:
- `action: "report"`: Returns full `ThreatModelObservabilityReport` in JSON format.
- `action: "summary"`: Returns high-level summary with health status, total count, critical unmitigated count, and overall risk score.
