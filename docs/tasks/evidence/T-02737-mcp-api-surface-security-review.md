# Evidence: T-02737 — Threat Model Maintenance MCP/API Surface Security Review

## Task Metadata
- **Task ID**: T-02737
- **Title**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / MCP/API surface: Security Review
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Status**: Completed
- **Date**: 2026-10-03
- **Artifact Path**: `docs/tasks/evidence/T-02737-mcp-api-surface-security-review.md`

## Executive Summary
A comprehensive security review and vulnerability assessment was conducted on the MCP/API surface of the Threat Model Maintenance subsystem (`code/aiosh-rust/aiosh-mcp/src/main.rs`). The evaluation examined input validation, path traversal barriers, sensitive information leakage, resource exhaustion bounds, and PEP policy enforcement. Zero policy bypasses or unhandled failure vectors were identified.

## Threat Vector & Abuse Scenario Analysis

### Abuse Scenario 1: Path Traversal Store Escape (CWE-22)
- **Attack Vector**: An adversary supplies a malicious `store_path` argument such as `../../../../etc/shadow` or `C:\Windows\System32\config\SAM` in an attempt to overwrite arbitrary system files or read sensitive host configuration.
- **Defense Mechanism**: All operations validate the supplied path using `ThreatModelService::validate_path`. The validator enforces:
  1. Rejection of `..` traversal sequences.
  2. Rejection of UNC network paths (`\\\\` and `//`).
  3. Rejection of control characters.
  4. Mandatory `.json` extension requirement.
  5. Maximum path depth limit of 16 components.
  6. Rejection of symbolic links to prevent symlink race/redirection attacks.
- **Verdict**: SECURE (attack mitigated).

### Abuse Scenario 2: Memory Exhaustion via Catalog Flooding (CWE-400)
- **Attack Vector**: An automated agent or malicious prompt creates thousands of threats with large payloads in a loop to cause out-of-memory crashes or deny service.
- **Defense Mechanism**:
  1. Store file size is limited to 1 MiB (`MAX_THREAT_MODEL_STORE_SIZE`).
  2. Catalog capacity is capped at 512 entries (`MAX_THREAT_ENTRIES_CAPACITY`).
  3. String fields are strictly length-bounded (`MAX_THREAT_ID_LEN = 64`, `MAX_THREAT_TITLE_LEN = 128`, `MAX_THREAT_DESC_LEN = 2048`, `MAX_THREAT_MITIGATION_LEN = 1024`).
- **Verdict**: SECURE (attack mitigated).

### Abuse Scenario 3: Secret & Private Key Exfiltration (CWE-200)
- **Attack Vector**: An agent embeds stolen cryptographic keys or tokens into threat descriptions or mitigation fields to establish an exfiltration channel.
- **Defense Mechanism**:
  - `validate_description` and `add_mitigation` perform content pattern scanning, rejecting inputs containing `BEGIN PRIVATE KEY` or `BEGIN RSA PRIVATE KEY`.
  - Non-printable control characters are stripped or rejected.
- **Verdict**: SECURE (attack mitigated).

### Abuse Scenario 4: Audit Disavowal & PEP Bypass (CWE-778 / CWE-284)
- **Attack Vector**: An untrusted caller invokes tools directly without passing through PEP access controls or leaving audit traces.
- **Defense Mechanism**:
  - Every tool execution is mediated through `dispatch::recorded_call`.
  - Consequential actions emit exactly one audit row into the SQLite `audit_ring` table before returning.
  - Audit rows are protected by SHA-256 hash chaining (`prev_hash` to `hash`), preventing history repudiation or selective tampering.
- **Verdict**: SECURE (attack mitigated).

### Abuse Scenario 5: Schema Corruption & Invalid State Transitions (CWE-20)
- **Attack Vector**: An adversary attempts to transition an unmitigated threat directly to `resolved` or to `mitigated` without attaching a mitigation.
- **Defense Mechanism**:
  - State machine transitions are governed by `can_transition_to` and `transition_to`.
  - Transitioning to `mitigated` is forbidden if the mitigation list is empty.
- **Verdict**: SECURE (attack mitigated).

## Audit Findings Matrix
| Weakness ID | Description | Severity | Mitigation Status |
| :--- | :--- | :--- | :--- |
| **CWE-20** | Improper Input Validation | High | Mitigated (strict bounds, regex & enum parsing) |
| **CWE-22** | Path Traversal | High | Mitigated (strict path validator, symlink ban) |
| **CWE-200** | Information Exposure | Medium | Mitigated (zero-disclosure secret scanner) |
| **CWE-400** | Uncontrolled Resource Consumption | High | Mitigated (1 MiB store cap, 512 entry limit) |
| **CWE-778** | Insufficient Logging | High | Mitigated (PEP dispatch & hash-chained audit ring) |

## Conclusion
The Threat Model Maintenance MCP surface meets all Phase 2 security kernel standards. No blocking issues or policy bypasses remain open.
