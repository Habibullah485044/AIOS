# T-02697: Secrets Handling Recovery & Validation Security Review

- **Task**: `T-02697`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Secrets Handling / recovery & validation
- **Date**: 2026-10-03
- **Status**: PASSED (Security Review Complete)

## 1. Threat Modeling & Scope
Audited `SecretRecoveryService`, `SecretIntegrityReport`, `SecretRecoveryReport`, atomic staging routines, quarantine serialization, and CLI subcommands (`aiosh secret recovery <check|backup|restore|repair>`) against the AIOS Threat Model and Common Weakness Enumerations (CWEs).

## 2. CWE Analysis & Audit Matrix

| CWE | Vulnerability Class | Vector & Scenario | Audit Finding & Applied Mitigation | Status |
|---|---|---|---|---|
| **CWE-22** | Path Traversal / Directory Climbing | Operator supplies `../../etc/vault.json` or relative path climbing in `--store`. | **Mitigated**: `SecretRecoveryService::validate_path()` rejects strings containing `..`, null bytes, or ASCII control characters fail-closed. | VERIFIED |
| **CWE-367** | Time-of-Check to Time-of-Use (TOCTOU) | Concurrently running processes attempting backup or repair clobbering each other. | **Mitigated**: Mutations utilize atomic file writes to staging files (`.tmp.bak`, `.tmp.repair`, `.tmp.restore`) followed by atomic rename (`fs::rename`). | VERIFIED |
| **CWE-200 / CWE-312** | Information Disclosure in Quarantine / Telemetry | Secret payloads or keys leaked in quarantine dumps (`<path>.corrupt.<ts>.json`) or integrity reports. | **Finding for Hardening (T-02698)**: Quarantine records must scrub `payload_hex` values and replace them with `[QUARANTINED_SCRUBBED_PAYLOAD]` before writing to disk to prevent cleartext disclosure. | ACTION PLANNED |
| **CWE-400** | Resource Exhaustion (DoS) | Malicious actor feeds a 10 GB file to exhaust memory during JSON deserialization. | **Mitigated**: Strict pre-read file size check enforces `metadata.len() <= MAX_SECRETS_STORE_SIZE` (1 MiB), rejecting oversized files fail-closed. | VERIFIED |
| **CWE-150 / CWE-116** | Terminal Escape Sequence Injection | Malicious secret IDs or error details containing ANSI control codes executed in terminal. | **Mitigated**: CLI routes all messages and error strings through `sanitize_terminal()`, replacing escape codes with `\u{FFFD}`. | VERIFIED |

## 3. Remediation & Hardening Actions for T-02698
1. **Quarantine Payload Scrubbing**: In `repair_vault()`, sanitize quarantined records by wiping `payload_hex` with `"[SCRUBBED_ON_QUARANTINE]"` to prevent residual credential exposure on disk.
2. **Path Hardening**: Disallow Windows UNC paths and absolute path prefixes containing double backslashes in `validate_path()`.
