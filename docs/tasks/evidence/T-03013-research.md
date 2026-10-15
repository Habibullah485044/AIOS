# Research: Automated Tests for Incident Response Runbooks (T-03013)

**Task ID**: T-03013 (Phase 2 — Security Kernel & PEP Fabric / Incident Response Runbooks / automated tests: Research)  
**Contract**: `docs/SPEC-INCIDENT-RUNBOOK-CONFIG.md`, `docs/SPEC-INCIDENT-RUNBOOK-CLI.md`, `docs/SPEC-INCIDENT-RUNBOOK-MCP.md`  
**Date**: 2026-10-15  
**Status**: COMPLETE — Established facts, constraints, authoritative standards, and prior art for the automated test suite of Incident Response Runbooks. No code changed.

---

## 1. Authoritative Sources & Regulatory Citations

1. **NIST Special Publication 800-61 Revision 2**:
   *Computer Security Incident Handling Guide* (August 2012). Establishes formal incident response lifecycle phases: Preparation, Detection & Analysis, Containment, Eradication & Recovery, and Post-Incident Activity (§3.1-§3.4). Mandates automated containment procedures with human-in-the-loop gates for high-impact actions.
2. **CISA Incident Response Playbooks**:
   *Federal Government Cybersecurity Incident and Vulnerability Response Playbooks* (November 2021). Specifies structured playbooks for malware containment, unauthorized access isolation, and credential revocation. Requires repeatable automated workflows, strict parameter sanitation, and forensic telemetry preservation.
3. **MITRE ATT&CK Framework & D3FEND**:
   Incident response countermeasure mapping (e.g., D3-PB Process Isolation, D3-NPA Network Traffic Filtering, D3-ERA Execution Eradication). Automated containment execution must guarantee verifiable termination without collateral operational disruption.
4. **AIOS Architectural Decisions & Invariants**:
   - `ADR-0035`: Security Kernel Policy Enforcement Point (PEP) Fabric & Fail-Closed Gate.
   - `ADR-0036`: Incident Response Runbooks, Execution State Machine, and Concurrency Limits.
   - `ADR-0037`: Proof of Restraint (Negative Attestation & Capability Token Redemption).
   - `PoR Invariant I-2`: Consequential actions (process kill, network route change, file removal) cannot execute without consuming a single-use capability token.

---

## 2. Established Facts vs Assumptions

### Established Facts
- **Fact 1 (Cross-Substrate Dual Implementation)**:
  - Rust Core Substrate: `aiosh-core::incident_runbook_data_model`, `aiosh-core::incident_runbook_service`, `aiosh-core::sec_tools`, `aiosh-core::runbook_config`.
  - Python MCP Substrate: `aiosh_mcp.incident_runbook_data_model`, `aiosh_mcp.incident_runbook_service`, `aiosh_mcp.incident_runbook_mcp`, `aiosh_mcp.runbook_config`.
  - Both share byte-stable catalog schemas and execution state semantics.
- **Fact 2 (PEP Gating & Proof of Restraint)**:
  - All state-changing runbook operations (`start`, `step`, `confirm`, `abort`, `init`) and network/file scans are subject to PEP gate evaluation (`_recorded_mcp_call` / `dispatch::commit`).
  - High-risk containment steps strictly require operator confirmation tokens (`requires_confirmation` or `is_high_risk()`).
- **Fact 3 (Precedence & Limits)**:
  - Configuration uses the 4-level precedence ladder: Argument > Environment Variable > Configuration File (`docs/runbook_config.json`) > Built-in Defaults.
  - Active session limit is bounded `[1, 10000]` (default 1000); step timeouts bounded `[1, 86400]` (default 3600); config files bounded to 64 KiB.
- **Fact 4 (Forensic Scanning Substrate)**:
  - Native tools support `scan_net` (port enumeration), `scan_files` (regex IOC hunting), and `scan_web` (endpoint discovery). All enforce path traversal rejection (`..`), control character scrubbing, and recursion depth caps.

### Assumptions
- **Assumption 1**: Automated tests should follow the established Phase 2 pattern (`test_incident_runbook_automated.rs` in Rust and `test_incident_runbook_automated_smoke.py` in Python) specifying 10 formal automated test vectors (`AUTORUNBOOK1`..`AUTORUNBOOK10`).
- **Assumption 2**: Automated tests should execute in completely isolated temporary directories and mock namespaces without touching host system processes or live production networks.

---

## 3. Prior Art in AIOS

The AIOS Phase 2 automated test suites serve as direct prior art:
- `code/aiosh-mcp/tests/test_compliance_automated_smoke.py` & `code/aiosh-rust/aiosh-core/tests/test_compliance_automated.rs`:
  Implemented 10 formal vectors (`AUTOCOMPLIANCE1`..`AUTOCOMPLIANCE10`) covering schema validation, status transitions, bounds, PEP gating, and concurrent mutation.
- `code/aiosh-mcp/tests/test_threat_model_automated_smoke.py`:
  Automated validation of threat modeling transitions, CVSS scoring, and audit chain monotonicity.
- `code/aiosh-mcp/tests/test_pep_grant_automated_smoke.py`:
  Automated testing of capability grant delegation, expiration, and cascade revocation.

---

## 4. Proposed Automated Verification Vectors (AUTORUNBOOK1..AUTORUNBOOK10)

| Vector ID | Target Property / Component | Description |
|---|---|---|
| **AUTORUNBOOK1** | **Catalog Snapshot & Spec Validation** | Validates baseline catalog loading (`RB-IR-MALWARE-01`, `RB-IR-ACCESS-01`), step sequence integrity, phase transitions, and schema invariants. |
| **AUTORUNBOOK2** | **Session State Machine Progression** | Asserts valid lifecycle transitions (`Pending` -> `Running` -> `AwaitingConfirmation` -> `Completed`), rejecting invalid jumps or advancements from terminal states. |
| **AUTORUNBOOK3** | **High-Risk Operator Confirmation Gate** | Proves that steps requiring confirmation or flagged high-risk cannot advance without explicit operator approval (`operator_confirmed: true`). |
| **AUTORUNBOOK4** | **Parameter Extraction & Interpolation** | Validates parameter syntax `{{param}}`, prevents parameter injection, rejects unknown parameters, and enforces length bounds `<= 256` bytes. |
| **AUTORUNBOOK5** | **Forensic File Pattern Scanning (ripgrep-grade)** | Asserts regex file IOC detection with depth bounding (`max_depth <= 32`), file size caps (16 MiB), and output line clamping. |
| **AUTORUNBOOK6** | **Network & Web Scanning Hygiene** | Verifies TCP connect scanning and web fuzzing, rejecting path traversals (`..`), null bytes (`\0`), and out-of-range port numbers. |
| **AUTORUNBOOK7** | **Configuration Ladder Resolution** | Asserts 4-level precedence ladder (Arg > Env > File > Default) and source provenance tracking across both substrates. |
| **AUTORUNBOOK8** | **Dynamic Concurrency & Eviction Capping** | Verifies that active sessions exceeding `max_active_sessions` evict oldest completed/idle sessions cleanly without memory leaks. |
| **AUTORUNBOOK9** | **PEP Authorization & Audit Trail** | Proves every consequential runbook or scan operation writes exactly one immutable audit record into SQLite `audit_ring`. |
| **AUTORUNBOOK10** | **Fail-Closed Result Envelopes & Abort Paths** | Asserts that session aborts, parsing errors, and malformed inputs fail closed, emitting structured error codes (`RUNBOOK_ERR_*`, `RUNBOOKCONF_ERR_*`). |

---

## 5. Decisions Needed Before Specification (T-03014)

1. **Test Location & Test Harness Structure**:
   - Rust: `code/aiosh-rust/aiosh-core/tests/test_incident_runbook_automated.rs`.
   - Python: `code/aiosh-mcp/tests/test_incident_runbook_automated_smoke.py`.
2. **Substrate Mocking Strategy**:
   - High-impact containment commands (e.g. `kill -9 {{target_pid}}`, `ip link set {{target_iface}} down`) will run in simulated execution mode (`simulate_success: true`) or against isolated mock processes/directories in test environments.
3. **Invariants Certification Target**:
   - Certify invariants `AUTORB-INV1` through `AUTORB-INV5` and PoR Invariant `I-2`.
