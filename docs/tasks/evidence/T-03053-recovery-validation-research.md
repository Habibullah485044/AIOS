# Research: Incident Response Runbooks Recovery & Validation Subsystem (T-03053)

**Task ID**: T-03053 (Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / recovery & validation: Research)  
**Contract Reference**: ADR-0035 §I-1, ADR-0037 §D-1, PoR Invariant I-2  
**Date**: 2026-10-16  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: COMPLETE — Authoritative sources reviewed, facts vs assumptions established, architectural decisions documented.

---

## 1. Objective & Scope

Investigate crash resilience, state restoration, integrity checking, and recovery mechanisms for the Incident Response Runbooks subsystem in AIOS. The runbooks subsystem manages active incident response sessions, playbooks (`RB-IR-MALWARE-01`, `RB-IR-ACCESS-01`), configuration files (`aiosh.runbook.toml`), and runtime metrics.

The recovery subsystem must ensure:
1. Detection of corrupted or incomplete runbook configuration and session files.
2. Safe non-destructive integrity audits without side effects.
3. Atomic repairs with crash consistency.
4. Quarantine isolation of corrupted files to prevent silent data loss and aid post-mortem forensics.
5. Strict adherence to Proof-of-Restraint (PoR) Invariant I-2 (every recovery/repair action recorded in tamper-evident WAL).

---

## 2. Authoritative Sources & Citations

1. **NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)**:
   - Section 3.4 (Recovery): Rebuilding clean state, restoring baseline configurations, confirming that vulnerabilities are eradicated before resuming normal operational status.
2. **CISA Incident Response Playbooks (Executive Order 14028)**:
   - Playbook operational requirements: Containment and eradication artifacts must be forensically isolated (quarantined) rather than destroyed.
3. **POSIX.1-2017 & Linux Atomic File Replacement Semantics (`rename(2)`)**:
   - `rename(oldpath, newpath)` is guaranteed atomic on POSIX filesystems when both paths reside on the same filesystem mount, preventing torn files on power outage or kernel panic.
4. **ADR-0035 (Honest Audit Trails & Fail-Closed Gates)**:
   - §AF-2: Standardized Result Envelope pattern; degraded and corrupted operations must emit honest audit records instead of silently masking errors.
5. **ADR-0037 (Proof of Restraint & Tamper-Evident WAL)**:
   - Invariant I-2: Zero state-changing operations occur without authorization token verification and immutable audit row commitment.

---

## 3. Facts vs. Assumptions

### Facts Established from Codebase
- **Fact 1**: The canonical runbook catalog is defined in `code/aiosh-rust/aiosh-core/src/incident_runbook_data_model.rs` and `code/aiosh-mcp/aiosh_mcp/incident_runbook_data_model.py` via `RunbookCatalogSnapshot::canonical_baseline()`.
- **Fact 2**: Incident runbook sessions are stateful in-memory sessions tracked in `_ACTIVE_SESSIONS` with transitions (`ACTIVE -> COMPLETED / FAILED / ABORTED`) in `incident_runbook_service.py` and `incident_runbook_service.rs`.
- **Fact 3**: Configuration precedence resolves `aiosh.runbook.toml` with size limits of 64 KiB (`MAX_RUNBOOK_CONFIG_FILE_SIZE = 64 * 1024`).
- **Fact 4**: The established recovery pattern in adjacent Phase 2 subsystems (`compliance_recovery`, `threat_model_recovery`, `secrets_recovery`) uses an enum status (`Healthy`, `Degraded`, `Corrupted`, `Missing`), timestamped quarantine (`.quarantine.<timestamp>`), max quarantine cap (`MAX_QUARANTINE_FILES = 10`), and atomic rename.
- **Fact 5**: All FastMCP mutations require a valid capability grant or confirmation token and route through `_recorded_mcp_call`.

### Assumptions Validated
- **Assumption 1**: The runbook recovery subsystem should support validating both persistent configuration files (`aiosh.runbook.toml`) and session snapshot stores (`runbook_state.json`).
- **Assumption 2**: In the event of catastrophic state corruption, the system should quarantine the corrupted file, reset the catalog snapshot to `canonical_baseline()`, and log an honest audit event detailing the corruption.
- **Assumption 3**: Quarantine rotation should preserve the most recent 10 files and purge older ones to bound disk utilization.

---

## 4. Key Architectural Decisions Needed

1. **Storage Target**:
   - Primary state recovery target: `runbook_state.json` and `aiosh.runbook.toml`.
2. **Issue Severities**:
   - Three severity tiers: `Warning` (e.g. unknown tag, near max active sessions), `Error` (e.g. invalid step target, non-fatal syntax), `Critical` (e.g. invalid JSON, missing canonical ID, path traversal).
3. **FastMCP Actions**:
   - Expose `validate`, `repair`, and `snapshot` under `aios_runbook`.
4. **Result Envelope**:
   - Standardize on `RunbookRecoveryResultEnvelope` complying with ADR-0035 §AF-2.
