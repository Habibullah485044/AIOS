# T-02717: Threat Model Maintenance Core Service Security Review

- **Task**: `T-02717`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / core service
- **Date**: 2026-10-03
- **Status**: PASSED (Security Review Complete)

## 1. Threat Modeling & Scope
Conducted security audit of `ThreatModelService` across lifecycle mutations, risk evaluation, filesystem persistence, and inter-process concurrency against AIOS Security Principles and Common Weakness Enumerations (CWEs).

## 2. CWE Analysis & Audit Matrix

| CWE | Vulnerability Class | Vector & Scenario | Audit Finding & Mitigations | Status |
|---|---|---|---|---|
| **CWE-22** | Path Traversal | Untrusted caller provides arbitrary paths (`../../etc/passwd` or UNC paths `\\evil\share`) to `load_from_path` / `save_to_path`. | **Mitigated**: `validate_path()` rejects `..`, UNC separators (`\\`, `//`), control characters, and non-JSON extensions. | VERIFIED |
| **CWE-367** | TOCTOU / File Overwrite Race | Concurrent invocations overwrite threat model state mid-write or corrupt JSON format. | **Finding for Hardening (T-02718)**: Enforce staged atomic writes via `.tmp` file and atomic rename; add advisory lock guard check. | ACTION PLANNED |
| **CWE-400** | Resource Exhaustion (DoS) | Oversized JSON payloads or unbounded threat lists consuming memory/disk. | **Mitigated**: `MAX_THREAT_ENTRIES_CAPACITY = 512` and `MAX_THREAT_MODEL_STORE_SIZE = 1 MiB` verified before read/parse. | VERIFIED |
| **CWE-200** | Information Disclosure | Error messages leaking sensitive host directory structures or system details. | **Mitigated**: Generic sanitized error messages with specific error code prefixes (`THREATSVC_ERR_*`). | VERIFIED |
| **CWE-840** | State Mutation Inconsistency | Malicious attempts to transition resolved threats or downgrade risk score maliciously. | **Mitigated**: Domain state machine rules strictly enforced during `update_status` and `attach_mitigation`. | VERIFIED |

## 3. Remediation & Hardening Actions for T-02718
1. **Atomic Staged Persistence**: When saving to path, write to temporary sibling file (`<target>.tmp.<pid>`) before atomically renaming to target path, ensuring zero corruption during concurrent crashes.
2. **Symlink / Reparse Point Validation**: Reject writing through symlinks or junction points to prevent symlink race attacks on Windows/POSIX.
3. **Strict Path Extension & Depth Boundary**: Limit relative directory depth to prevent deeply nested directory creation.
