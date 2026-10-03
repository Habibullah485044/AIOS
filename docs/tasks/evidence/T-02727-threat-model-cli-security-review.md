# T-02727: Threat Model Maintenance CLI Surface Security Review

- **Task**: `T-02727`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / CLI surface
- **Date**: 2026-10-03
- **Status**: PASSED (Security Review Complete)

## 1. Security Scope & Context
Audited the `aiosh threat` CLI surface implementation in `code/aiosh-rust/aiosh-cli/src/main.rs` against AIOS Security Principles, terminal injection hazards, and Common Weakness Enumerations (CWEs).

## 2. CWE Analysis & Audit Matrix

| CWE | Vulnerability Class | Vector & Scenario | Audit Finding & Mitigations | Status |
|---|---|---|---|---|
| **CWE-20** | Improper Input Validation | Malformed flags, empty IDs, or unsupported categories supplied to CLI commands. | **Mitigated**: Strict parser validation via `parse_category`, `parse_severity`, `parse_status`, and `ThreatEntry::new`. | VERIFIED |
| **CWE-150 / CWE-116** | Terminal Escape & Control Character Injection | Malicious threat titles containing ANSI escapes (`\x1b`) altering terminal state or log displays. | **Finding for Hardening (T-02728)**: Enforce `sanitize_terminal_output` across all stdout print statements in `list` and `show`. | ACTION PLANNED |
| **CWE-22** | Path Traversal | Specifying arbitrary directories via `--path` (`../../etc/passwd` or UNC paths). | **Mitigated**: Early validation via `ThreatModelService::validate_path` rejects traversal, UNC paths, and symlinks. | VERIFIED |
| **CWE-200** | Information Disclosure | Plaintext credentials or internal system paths disclosed in error envelopes or output streams. | **Mitigated**: Zero-disclosure scanners in domain model reject private keys; error messages sanitized. | VERIFIED |
| **CWE-778** | Insufficient Audit Logging | Invocations failing to register immutable audit traces in SQLite ring. | **Mitigated**: All code paths execute `classify_and_emit` logging actor, command, outcome, and metadata. | VERIFIED |

## 3. Remediation & Hardening Actions for T-02728
1. **Terminal Output Sanitization**: Wrap all dynamic fields (ID, title, description, component, mitigations) in `sanitize_terminal_output` to prevent terminal ANSI escape injection.
2. **Standardized JSON Error Envelopes**: Ensure all JSON errors consistently format with `{ "code": <exit_code>, "error": { "code": <ERR>, "message": <MSG> } }`.
3. **Audit Target Tagging**: Populate `target` parameter in `classify_and_emit` with threat ID when available.
