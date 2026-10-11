# Research Document: Compliance Mapping Observability (T-02933)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Observability
- **Task ID**: `T-02933`
- **Focus**: Observability, Telemetry, Distribution Metrics, and Audit Correlation
- **Authoritative Standards & RFCs**:
  - RFC 3339: Date and Time on the Internet: Timestamps
  - NIST SP 800-53 Rev. 5: Security and Privacy Controls for Information Systems and Organizations (AU-6 Audit Record Review, Analysis, and Reporting)
  - ISO/IEC 27001:2022 Control 8.15: Logging and Monitoring
  - AIOS ADR-0035 (Security Architecture) & ADR-0037 (Proof of Restraint)

---

## 1. Executive Summary

The Compliance Mapping Observability subsystem establishes continuous monitoring, point-in-time metrics aggregation, framework coverage telemetry, lifecycle status distributions, policy posture auditing, and audit log correlation for AIOS regulatory compliance. 

Observability must be read-only, non-disruptive, bounded against resource exhaustion (CWE-400), sanitized against log injection (CWE-117), and free of confidential data leakage (CWE-532).

---

## 2. Invariants & Metrics Requirements

| Invariant | Name | Description |
|:---|:---|:---|
| `COMPOBS1` | **Temporal & Timestamp Integrity** | Reports must include RFC 3339 UTC timestamps (`generated_at_utc`). |
| `COMPOBS2` | **Framework & Target Distributions** | Distribution metrics across regulatory frameworks (`mappings_by_framework`) and target components (`mappings_by_target_type`). |
| `COMPOBS3` | **Lifecycle Status Progression** | Distribution map tracking mappings across compliance statuses (`mappings_by_status`: `compliant`, `partially_compliant`, `non_compliant`, `not_applicable`). |
| `COMPOBS4` | **Compliance Posture Scoring** | Deterministic score metrics (`compliance_percentage`, `gap_control_count`, `total_mappings`). |
| `COMPOBS5` | **Policy Mode, Capacity & Health Telemetry** | Reflection of active policy mode (`enforcing`, `permissive`, `disabled`, `unconfigured`), capacity utilization percentage (`capacity_utilization_percent`), and system health assertion (`is_healthy`). |
| `COMPOBS6` | **Audit Trail Correlation** | Aggregation of recent audit events from `AuditRing` (`recent_audit_events_count`) filtered by `tool == "compliance"` or prefix `aios.compliance`. |

---

## 3. Fact vs. Assumption Separation

### 3.1 Facts
1. **Existing Core Substrates**: `ComplianceService` (`code/aiosh-rust/aiosh-core/src/compliance_service.rs`) and `ComplianceCatalogSnapshot` maintain regulatory mapping states and can perform assessment queries via `assess_compliance()`.
2. **Audit Substrate**: `AuditRing` (`code/aiosh-rust/aiosh-core/src/audit.rs`) maintains an append-only WAL ring buffer supporting tail inspection (`tail(limit: i64)`).
3. **Capacity Constraints**: Compliance stores are capped at 1024 entries and 1 MiB (`MAX_COMPLIANCE_STORE_SIZE`).
4. **Current MCP Gaps**: `code/aiosh-mcp/aiosh_mcp/compliance.py` supports actions `("list", "show", "register", "status", "assess", "check-pep", "init")`, but lacks an observability report action (`stats`).
5. **Architectural Prior Art**: Similar observability modules exist in `threat_model_observability.rs`, `capability_observability.rs`, `pep_observability.rs`, and `session_observability.rs`.

### 3.2 Assumptions
1. Operators and automated agents require single-call consolidated telemetry without modifying store state.
2. Sanitization must filter control characters and restrict text bounds to 256 characters (`MAX_TELEMETRY_TEXT_LEN = 256`).
3. Distribution mappings must be capped at 128 distinct entries (`MAX_OUTCOME_DISTRIBUTION_ENTRIES = 128`) to prevent memory exhaustion attacks.
4. Audit inspection bounded to 1,000 items (`MAX_AUDIT_LOG_TAIL_ITEMS = 1000`) provides sufficient temporal locality while preserving O(1) bounded latency.

---

## 4. Unknowns & Decisions Needed

- **Decision D1 (Action Dispatch & Surface)**: Extend `aios.compliance` with read-only action `stats` (parity with `aios.service.stats` and `aios.session.stats`).
- **Decision D2 (Cross-Substrate Parity)**: Implement report generation in both Rust `aiosh-core` (`compliance_observability.rs`) and Python `aiosh-mcp` (`compliance.py`).
- **Decision D3 (Error Taxonomy)**: Define error codes `COMPOBS_ERR_VALIDATION` and `COMPOBS_ERR_SERVICE_INACCESSIBLE`.
- **Decision D4 (Health Criteria)**: System is healthy (`is_healthy = true`) when `total_mappings <= 1024` and no catalog corruption exists.
- **Decision D5 (Sanitization Bound)**: Remove all control characters, trim whitespace, and clamp to 256 bytes for all telemetry labels.
- **Decision D6 (PoR Compatibility)**: As a read-only observability action, `stats` requires no capability mint/redeem tokens but records a read-only audit row per call.

---

## 5. Next Steps
- **T-02934**: Author formal normative specification `docs/SPEC-COMPLIANCE-OBSERVABILITY.md`.
- **T-02935**: Scaffold data structures in `compliance_observability.rs` and Python module.
