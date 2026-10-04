# T-02827: Compliance Mapping CLI Surface Security Review

- **Task**: `T-02827`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / CLI surface
- **Date**: 2026-10-04
- **Status**: PASSED

## 1. Threat Modeling & Abuse Scenarios

### Scenario A: Path Traversal & Symlink Exploitation (CWE-22 / CWE-59)
- **Vector**: Hostile operator or compromised agent supplies `--path ../../../etc/compliance.json` or points `--path` to a symbolic link pointing to sensitive system files.
- **Verification**: `ComplianceService::validate_path` rejects relative traversals containing `..`, network UNC shares (`\\\\` / `//`), paths with control characters, non-json extensions, and checks `fs::symlink_metadata` to block symlinks.
- **Verdict**: Mitigated with exit code 2 and failure audit row emission.

### Scenario B: Terminal Escape Injection (CWE-116 / CWE-150)
- **Vector**: Attacker injects VT100/ANSI escape codes into mapping IDs, controls, or mitigation descriptions to hide malicious actions or hijack terminal sessions.
- **Verification**: All dynamic outputs printed to stdout/stderr are filtered through `sanitize_terminal_output` or `sanitize_terminal`, converting illegal control codes to `\u{FFFD}`.
- **Verdict**: Mitigated.

### Scenario C: Malformed Input & Resource Exhaustion (CWE-20 / CWE-400)
- **Vector**: Flooding catalog with oversized text, deeply nested directories, or corrupt frameworks.
- **Verification**: `ComplianceMappingEntry::new` validates bounds: IDs capped at 64 chars, titles at 256 chars, descriptions at 4096 chars, tags at 32 items. Store file bounded at 1 MiB (`MAX_COMPLIANCE_STORE_SIZE`).
- **Verdict**: Mitigated.

### Scenario D: State Mutation Audit Evasion (CWE-778)
- **Vector**: Executing `register`, `status`, or `init` without generating evidence or logs.
- **Verification**: Invariant `COMPLYCLI1` is enforced: every single command branch calls `classify_and_emit` to write a row into the SQLite WAL audit ring with classifier evaluation and timestamp.
- **Verdict**: Mitigated.

## 2. Security Posture Summary
Zero open security findings. All abuse scenarios tested and verified safe.
