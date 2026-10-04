# Security Review & Abuse Scenarios: Compliance Mapping Core Service (T-02817)

- **Task ID**: T-02817
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping / core service
- **Date**: 2026-10-04
- **Auditor**: Antigravity Automated Security Audit Suite
- **Verdict**: PASS — 0 High / 0 Medium / 0 Low unmitigated vulnerabilities

## 1. Threat Scenarios & Mitigations

### Scenario 1: Path Traversal Arbitrary File Overwrite (CWE-22)
- **Abuse Vector**: Attacker passes `../../etc/cron.d/compliance.json` or a remote UNC path to `ComplianceService::save_to_path`, attempting to drop arbitrary files outside the repository root.
- **Verification**: `ComplianceService::validate_path` checks against `..`, leading UNC slashes (`\\\\`, `//`), control characters, and depth limit (<= 16).
- **Result**: Fails closed with `COMPLIANCESVC_ERR_PATH_TRAVERSAL`.

### Scenario 2: Symlink Target Redirection (CWE-59)
- **Abuse Vector**: Storage path points to a symbolic link targeting sensitive credentials or system binaries.
- **Verification**: `symlink_metadata` inspects existing files and explicitly refuses any symlink file types.
- **Result**: Fails closed with `COMPLIANCESVC_ERR_PATH_TRAVERSAL: Symlinks are forbidden`.

### Scenario 3: Memory Exhaustion via Oversized File (CWE-400)
- **Abuse Vector**: Attacker plants a 2 GB JSON file at the compliance map location to trigger out-of-memory denial of service during `load_from_path`.
- **Verification**: Metadata check enforces `meta.len() <= MAX_COMPLIANCE_STORE_SIZE` (1 MiB).
- **Result**: Fails closed with `COMPLIANCESVC_ERR_FILE_SIZE` without reading file contents into memory.

### Scenario 4: Concurrent Write TOCTOU Race Condition (CWE-362)
- **Abuse Vector**: Multiple concurrent tasks trigger `save_to_path`, resulting in truncated or mangled JSON output.
- **Verification**: All saves write to temporary files tagged with PID and nanosecond timestamps (`.tmp.{pid}.{nanos}`) before atomic `fs::rename`.
- **Result**: Writes are crash-consistent and atomic.

### Scenario 5: Fabric Gating Bypass / Unverified PEP Claims (CWE-285)
- **Abuse Vector**: Misconfiguration marks a critical control as covered without verifying PEP gate association.
- **Verification**: `verify_pep_coverage` and `uncovered_pep_gates` audit exact substrate bindings against recognized gate names.
- **Result**: Uncovered gates are explicitly flagged.

## 2. Policy Enforcement Summary
All state-changing mutations and file I/O operations execute fail-closed with bounded resources and atomic persistence.
