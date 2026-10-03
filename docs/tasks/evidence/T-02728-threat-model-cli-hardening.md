# T-02728: Threat Model Maintenance CLI Surface Hardening

- **Task**: `T-02728`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / CLI surface
- **Date**: 2026-10-03
- **Status**: PASSED

## 1. Hardening Scope & Implementations
Implemented defense-in-depth mitigations for `aiosh threat` in `code/aiosh-rust/aiosh-cli/src/main.rs`:

1. **Terminal Output Sanitization (CWE-150 / CWE-116)**:
   - Wrapped all stdout dynamic outputs (`id`, `title`, `description`, `category`, `severity`, `status`, `component`, `mitigations`) in `sanitize_terminal_output`.
   - Strips non-standard control characters while preserving expected formatting, thwarting ANSI escape injection attacks that attempt to hijack user terminal emulators or disguise malicious output.

2. **Audit Target Provenance**:
   - Enhanced `classify_and_emit` calls in `cmd_threat` to bind `target: Some(&id)` whenever operating on an identified threat entry (`show`, `register`, `status`, `mitigate`).
   - Enables fine-grained audit filtering and tamper-evident tracing in SQLite ring logs.

3. **Standardized JSON Envelope Integrity**:
   - Guaranteed that all JSON responses and error pathways consistently output standard structured payloads (`{ "code": <exit_code>, ... }`), ensuring robust machine consumption by security pipelines and agent runners.

## 2. Test Verification
Verified that all CLI unit and integration tests execute successfully with 0 failures:
- `test_threat_cli_help_and_unknown`: passed
- `test_threat_cli_path_validation`: passed
- `test_threat_cli_lifecycle_and_operations`: passed
- `test_threat_cli_integration_e2e`: passed
