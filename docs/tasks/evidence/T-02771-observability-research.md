# Research Document: Threat Model Observability (T-02771)

- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Maintenance
- **Focus**: Observability, Telemetry, and Metrics Reporting
- **Bindings**: ADR-0035 §G-1, ADR-0036 §C-2

## 1. Executive Summary
The Threat Model Observability subsystem provides point-in-time metrics aggregation, STRIDE category distributions, severity distributions, lifecycle status progression tracking, risk exposure scoring, and audit event auditing for Threat Model Maintenance. It ensures operators and automated agents have continuous visibility into the security posture of AIOS without compromising confidentiality or risking denial of service.

## 2. Invariants & Metrics Requirements

| Invariant | Name | Description |
|:---|:---|:---|
| `THREATOBS1` | **Timestamp & Temporal Integrity** | Reports must include RFC3339 UTC timestamps (`generated_at_utc`). |
| `THREATOBS2` | **Taxonomy & Severity Distribution** | Distribution maps for STRIDE categories (`threats_by_category`) and severity levels (`threats_by_severity`). |
| `THREATOBS3` | **Lifecycle State Progression** | Distribution map tracking threats across lifecycle states (`threats_by_status`). |
| `THREATOBS4` | **Risk Exposure Metrics** | Integration of monotonic risk assessment metrics (`critical_unmitigated_count`, `overall_risk_score`). |
| `THREATOBS5` | **Policy & System Health** | Reflection of active policy mode (`enforcing`, `permissive`, `disabled`) and health assertion (`is_healthy`). |
| `THREATOBS6` | **Audit Trail Correlation** | Aggregation of recent audit events from `AuditRing` (`recent_audit_events_count`) filtering for `aios.threat.*` calls. |

## 3. Defense-in-Depth & Security Safeguards

1. **CWE-400 (Uncontrolled Resource Consumption)**:
   - Metric labels and textual keys sanitized to a maximum of 256 characters (`MAX_TELEMETRY_TEXT_LEN`).
   - Distribution maps bounded to at most 128 distinct entries (`MAX_OUTCOME_DISTRIBUTION_ENTRIES`).
   - Audit trail inspection limited to a bounded tail of 1,000 log records (`MAX_AUDIT_LOG_TAIL_ITEMS`).
2. **CWE-532 (Sensitive Information in Log Files / Metrics)**:
   - Telemetry strictly contains quantitative metrics and enum keys. No threat descriptions, mitigation bodies, or keys are emitted in the observability report.
3. **CWE-20 (Improper Input Validation)**:
   - Sanitization filters all non-printable ASCII and control characters before ingestion into telemetry tables.

## 4. MCP Interface Design
The observability metrics will be surfaced through the existing MCP server harness:
- Tool: `aios.threat.metrics` (or `aios.threat.observe`)
- Actions: `summary`, `distribution`, `health`

## 5. Next Steps
- `T-02772`: Author formal specification `SPEC-THREAT-MODEL-OBSERVABILITY.md`.
- `T-02773`: Scaffold `code/aiosh-rust/aiosh-core/src/threat_model_observability.rs`.
