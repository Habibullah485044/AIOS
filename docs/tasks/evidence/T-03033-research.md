# Research Document: Incident Response Runbooks Observability (T-03033)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / Observability
- **Task ID**: `T-03033`
- **Focus**: Observability, Telemetry, Phase Metrics, Scan Budgets, and Audit Correlation
- **Authoritative Standards & References**:
  - NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide (§3.4 Incident Metrics & §4 Incident Coordination)
  - RFC 3339: Date and Time on the Internet: Timestamps
  - RFC 5424: The Syslog Protocol
  - OpenTelemetry Specification: Semantic Conventions for Incidents, Security Events, and Diagnostics
  - AIOS ADR-0035 (Security Architecture), ADR-0036 (PEP Fabric), ADR-0037 (Proof of Restraint Invariants I-1, I-2)

---

## 1. Executive Summary

The Incident Response Runbooks Observability subsystem provides read-only monitoring, real-time telemetry aggregation, execution state analytics, phase progression distribution, scanning budget tracking, security policy compliance posture, and audit trail correlation.

Per ADR-0035 and ADR-0037, observability functions must be strictly non-state-changing (read-only), non-disruptive, bounded against resource exhaustion (CWE-400), sanitized against log and telemetry injection (CWE-117), and free of credential or sensitive artifact leakage (CWE-532).

---

## 2. Invariants & Telemetry Requirements

| Invariant | Name | Description |
|:---|:---|:---|
| `IROBS-INV1` | **Temporal & Timestamp Integrity** | Telemetry reports must include RFC 3339 UTC timestamps (`generated_at_utc`). |
| `IROBS-INV2` | **Execution Distribution & Status** | Aggregated run counts (`total_executions`), breakdown by category (`executions_by_category`: `malware`, `unauthorized_access`, `denial_of_service`, `data_exfiltration`), and status (`executions_by_status`: `active`, `completed`, `failed`, `aborted`). |
| `IROBS-INV3` | **Lifecycle Phase & Latency Tracking** | Step executions classified across NIST SP 800-61 phases (`preparation`, `detection`, `containment`, `eradication`, `recovery`, `post_incident`) with average step duration tracking. |
| `IROBS-INV4` | **Security Scanning Budgets** | Cumulative diagnostics metrics: `total_ports_scanned`, `total_files_scanned`, `total_web_paths_scanned`. |
| `IROBS-INV5` | **Policy & Proof-of-Restraint Posture** | Telemetry on policy enforcement mode (`enforcing`, `permissive`, `disabled`), high-risk confirmation count (`high_risk_confirmations_total`), policy rejections (`policy_rejections_total`), and capacity utilization (`active_sessions_utilization_percent`). |
| `IROBS-INV6` | **Audit Trail Correlation** | Aggregation of recent incident runbook audit records from `AuditRing` (`recent_audit_events_count`) filtered by prefix `incident_runbook` or `aiosh.runbook`. |

---

## 3. Fact vs. Assumption Separation

### 3.1 Facts
1. **Existing Core Substrates**: `RunbookCatalogSnapshot` and session management maintain runbook specifications (`code/aiosh-rust/aiosh-core/src/incident_runbook_data_model.rs`) and runtime execution states.
2. **Security Policy Substrate**: `RunbookSecurityPolicy` (`code/aiosh-rust/aiosh-core/src/incident_runbook_policy.rs` and `code/aiosh-mcp/aiosh_mcp/incident_runbook_policy.py`) evaluates start, step advance, and scan budgets.
3. **Audit Substrate**: `AuditRing` maintains an append-only WAL ring buffer supporting tail inspection (`tail(limit: i64)`).
4. **Current FastMCP Surface**: `incident_runbook_mcp.py` supports actions `start`, `step`, `abort`, `status`, `list`, `scan`, `policy`, but lacks a consolidated telemetry action `stats`.
5. **Architectural Precedent**: Similar observability reporting patterns exist across other Phase 2 subsystems (`threat_model_observability.rs`, `compliance_observability.rs`, `capability_observability.rs`).

### 3.2 Assumptions
1. Operators and SIEM/SOAR automation require single-call consolidated telemetry without modifying execution session state.
2. Distribution mappings and string labels must be capped at 128 distinct entries (`MAX_OBSERVABILITY_ENTRIES = 128`) and 256 characters (`MAX_OBSERVABILITY_TEXT_LEN = 256`) to prevent memory exhaustion attacks.
3. Telemetry snapshot payload must not exceed 64 KiB (`MAX_OBSERVABILITY_PAYLOAD_BYTES = 64 * 1024`).
4. Audit log tailing bounded to 1,000 items (`MAX_AUDIT_LOG_TAIL_ITEMS = 1000`) provides sufficient temporal locality with deterministic latency.

---

## 4. Unknowns & Decisions Needed

- **Decision D1 (Surface Dispatch)**: Extend FastMCP `incident_runbook` with read-only action `"stats"` (parity with `aios.compliance` and `aios.service`).
- **Decision D2 (Cross-Language Substrates)**: Implement report generation in both Rust `aiosh-core` (`incident_runbook_observability.rs`) and Python `aiosh-mcp` (`incident_runbook_observability.py`).
- **Decision D3 (Error Taxonomy)**: Define standard error constants `IROBS_ERR_VALIDATION` and `IROBS_ERR_INACCESSIBLE`.
- **Decision D4 (Health Criteria)**: System is healthy (`is_healthy = true`) when `active_sessions <= max_active_sessions`, catalog integrity is intact, and policy is in a valid state.
- **Decision D5 (Proof of Restraint Classification)**: As a strictly read-only observability action, `"stats"` does not redeem capability tokens (Invariant I-2 not triggered), but records a read-only audit row per call (Invariant I-1 satisfied).

---

## 5. Next Steps
- **T-03034**: Author formal normative specification `docs/SPEC-INCIDENT-RUNBOOK-OBSERVABILITY.md`.
- **T-03035**: Scaffold data structures in `incident_runbook_observability.rs` and Python module.
