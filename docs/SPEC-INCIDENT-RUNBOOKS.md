# Specification: Incident Response Runbooks Data Model (SPEC-INCIDENT-RUNBOOKS)

- **Status**: SPECIFIED
- **Date**: 2026-10-11
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Incident Response Runbooks
- **Binding**: NIST SP 800-61 Rev. 2, CISA Playbooks, ADR-0035 §I-1, ADR-0037 §D-1, PoR Invariant I-2
- **Source Code Target**:
  - Rust Core: `code/aiosh-rust/aiosh-core/src/incident_runbook_data_model.rs`
  - Python MCP: `code/aiosh-mcp/aiosh_mcp/incident_runbook_data_model.py`

---

## 1. Domain Types & Enums

### 1.1 IncidentSeverity
- `low`: Low impact anomaly or minor configuration deviation.
- `medium`: Contained threat or isolated policy alert.
- `high`: Active unauthorized access, credential abuse, or malware execution.
- `critical`: Subsystem compromise, audit tampering, or mass data exfiltration.

### 1.2 IncidentCategory
- `malware_containment`: Malicious binary execution, trojans, ransomware.
- `unauthorized_access`: Stolen credentials, rogue SSH, privilege escalation.
- `data_exfiltration`: Bulk unauthorized data transmission.
- `denial_of_service`: Resource starvation, network flooding.
- `integrity_violation`: Tampered binaries, unverified config changes.
- `policy_bypass_attempt`: Direct PEP evasion or ungranted capability invocation.

### 1.3 RunbookPhase
- `preparation`: Baseline verification and readiness inspection.
- `detection`: Indicator validation and forensic scoping.
- `containment`: Sandboxing, process freezing, firewall drops.
- `eradication`: Removing malware artifacts and invalidating tokens.
- `recovery`: Re-enabling services under verification.
- `post_incident`: Archival of forensic audit trails and post-mortem review.

### 1.4 RunbookTargetSubstrate
- `process`: Kernel process signals (`SIGSTOP`, `SIGKILL`), cgroups.
- `network`: Firewall packet drop, eBPF filter, socket teardown.
- `identity`: Capability token revocation, session invalidation.
- `audit_ring`: Forensic commit, hash chain integrity checkpoint.
- `storage`: Partition unmount, folder quarantine.

---

## 2. Structural Schemas

### 2.1 RunbookStep
```rust
pub struct RunbookStep {
    pub id: String,                    // e.g. "STEP-01"
    pub title: String,                 // e.g. "Freeze suspect process"
    pub phase: RunbookPhase,           // e.g. Containment
    pub target: RunbookTargetSubstrate,// e.g. Process
    pub action_template: String,       // e.g. "kill -STOP {pid}"
    pub automated: bool,               // can run unattended
    pub requires_confirmation: bool,   // needs operator sign-off
    pub timeout_seconds: u64,          // max bounded execution time
}
```

### 2.2 RunbookSpec
```rust
pub struct RunbookSpec {
    pub id: String,                    // e.g. "RB-MALWARE-CONTAINMENT"
    pub title: String,                 // Human-readable title
    pub category: IncidentCategory,
    pub severity: IncidentSeverity,
    pub description: String,
    pub steps: Vec<RunbookStep>,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}
```

### 2.3 RunbookCatalogSnapshot
```rust
pub struct RunbookCatalogSnapshot {
    pub version: String,
    pub runbooks: Vec<RunbookSpec>,
    pub generated_at: String,
}
```

---

## 3. Invariants & Validation Bounds

- `IR-INV1` (**ID Hygiene**): Alphanumeric characters with `_`, `-`, `.` only. Length bounded by `MAX_RUNBOOK_ID_LEN` (64).
- `IR-INV2` (**Control Character Proscription**): Zero control characters permitted in titles or descriptions (`RUNBOOK_ERR_CONTROL_CHARS`).
- `IR-INV3` (**Capacity & Size Bounds**): Maximum 32 steps per runbook, maximum 256 runbooks per catalog (`MAX_RUNBOOK_CATALOG_CAPACITY`), maximum 16 tags.
- `IR-INV4` (**Step Completeness**): Every runbook must specify at least one valid step (`RUNBOOK_ERR_EMPTY_STEPS`).
- `IR-INV5` (**Canonical Baseline**): Must provide a hardened baseline covering standard NIST SP 800-61 containment scenarios.
