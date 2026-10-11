# Research: Incident Response Runbooks Data Model (T-02963)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / Data Model
- **Task ID**: `T-02963`
- **Reviewer**: Antigravity Security Architect
- **Date**: 2026-10-11
- **Focus**: Industry standards, architectural bindings, data structures, and constraints for Incident Response Runbooks.

---

## 1. Authoritative Standards & Prior Art

### 1.1 NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)
NIST SP 800-61 defines the canonical 4-phase incident handling lifecycle:
1. **Preparation**: Maintaining incident handling capabilities, playbooks, security baselines, and detection tools.
2. **Detection & Analysis**: Evaluating attack indicators, classifying incident categories (e.g. DoS, Malicious Code, Unauthorized Access), determining scope, and assigning severity.
3. **Containment, Eradication & Recovery**:
   - Containment: Selecting a containment strategy (e.g. process freeze, network isolation, credential revocation) before evidence is destroyed.
   - Eradication: Purging malicious artifacts, restoring clean configurations.
   - Recovery: Restoring systems to clean operational state and validating security invariants.
4. **Post-Incident Activity**: Lessons learned, evidence preservation, and updating defensive rules.

### 1.2 CISA Incident Response Playbooks
CISA playbooks emphasize modular, declarative steps with explicit role boundaries, automated containment hooks, decision branch conditions, and chain-of-custody recording.

### 1.3 MITRE D3FEND Countermeasure Taxonomy
Defensive action classes mapped to runbook containment and remediation steps:
- **Model / Detect**: File analysis, process monitoring, network flow verification.
- **Isolate / Contain**: Network isolation, process termination, account suspension.
- **Deceive / Evict**: Capability revocation, token invalidation, memory dumping.

---

## 2. AIOS Architectural Fit & Kernel Substrates

In AIOS, an Incident Response Runbook is not merely a human markdown guide. It is a **machine-executable, PEP-governed security kernel policy**:
1. **Substrate Binding**: Every automated step must declare its targeted substrate:
   - `Process`: Process suspension (`SIGSTOP`), termination (`SIGKILL`), cgroup freezing.
   - `Network`: Firewall drop, socket closure, CIDR isolation.
   - `Identity`: Capability token revocation, session invalidation.
   - `AuditRing`: Forensic snapshot commitment, hash-chain verification.
   - `Storage`: Mount point unmount, filesystem quarantine.
2. **Proof-of-Restraint (PoR Invariant I-2)**:
   - Runbook activation and containment execution are consequential security actions.
   - Automated steps cannot execute without presenting and redeeming a valid capability token.
   - Every runbook execution must write an append-only audit row to `audit.db`.

---

## 3. Facts vs. Assumptions

| Category | Item | Classification | Verification / Evidence |
| :--- | :--- | :--- | :--- |
| **Fact** | PEP gates enforce capability tokens before actions execute. | **Fact** | Verified across all Phase 2 services (`aiosh-core::pep`). |
| **Fact** | Audit log is append-only, SHA-256 hash-chained SQLite WAL. | **Fact** | Verified in `aiosh_core::audit::AuditRing`. |
| **Fact** | Runbooks require strict input bounds to prevent DoS. | **Fact** | Max ID 64 chars, max title 128 chars, max 32 steps per runbook. |
| **Assumption** | Runbooks can be serialized into canonical JSON snapshots. | **Fact (Adopted)** | Parity with `compliance_map.json` and `threat_model.json`. |
| **Assumption** | Some steps may require operator confirmation before execution. | **Fact (Adopted)** | `step.requires_confirmation: bool` allows hybrid autonomous + human-in-the-loop workflows. |

---

## 4. Proposed Domain Primitives

1. **`IncidentSeverity`**:
   - `Low`, `Medium`, `High`, `Critical`.
2. **`IncidentCategory`**:
   - `MalwareContainment`, `UnauthorizedAccess`, `DataExfiltration`, `DenialOfService`, `IntegrityViolation`, `PolicyBypassAttempt`.
3. **`RunbookPhase`**:
   - `Preparation`, `Detection`, `Containment`, `Eradication`, `Recovery`, `PostIncident`.
4. **`RunbookStepAction`**:
   - `StepId`, `Title`, `Phase`, `SubstrateTarget`, `CommandTemplate`, `Automated`, `RequiresConfirmation`, `TimeoutSeconds`.
5. **`RunbookSpec`**:
   - `Id`, `Title`, `Description`, `Category`, `Severity`, `Steps`, `CreatedAt`, `UpdatedAt`.
6. **`RunbookCatalogSnapshot`**:
   - Canonical collection of active runbooks with version and baseline defaults.

---

## 5. Decisions Needed for Specification (T-02964)

1. **Storage Location**: Default runbook store file `docs/incident_runbooks.json` with fallback canonical baseline (parity with `compliance_map.json`).
2. **Execution Engine Separation**: The data model (`T-02963..T-02972`) defines declarative schemas and validators; the execution engine lives in core service (`T-02973..T-02982`).
3. **Identifier Format**: Strict alphanumeric with hyphens (e.g., `RB-IR-MALWARE-01`).
