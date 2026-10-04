# T-02828: Compliance Mapping CLI Surface Hardening

- **Task**: `T-02828`
- **Sub-Epic**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / CLI surface
- **Date**: 2026-10-04
- **Status**: PASSED

## 1. Hardening Measures Implemented & Verified

### A. Size Caps & Input Boundaries
- **Store Size Limit**: File read operations enforce `MAX_COMPLIANCE_STORE_SIZE` (1 MiB), preventing memory exhaustion attacks via oversized JSON payloads.
- **Entry Field Bounds**: Strict bounds are enforced across all input fields (`id` <= 64 chars, `title` <= 256 chars, `mitigation` <= 4096 chars, `tags` <= 32 items).
- **Argument Sanitization**: Path inputs reject control characters, non-.json extensions, relative `..` traversals, and UNC network shares.

### B. Standard Result Envelope & Zero Silent Failures
- **JSON Envelope**: When `--json` flag is supplied, errors are structured in standard schema `{"error": "<sanitized error message>", "code": <exit_code>}`.
- **Exit Code Semantics**:
  - `0`: Success.
  - `1`: Logical failure (e.g. ID not found, PEP gate uncovered, store already exists).
  - `2`: Validation, argument, or syntax error (e.g. illegal path, missing mandatory flag, invalid framework name).
- **Zero Silent Failure**: Every failure branch prints actionable, sanitized diagnostic info and terminates with a non-zero exit code.

### C. Resource Cleanup & RAII Lifecycles
- **File Descriptors**: File reads and atomic writes (`fs::write`, `fs::read_to_string`) are scoped with immediate RAII closure, ensuring zero descriptor leaks on both normal and panic/error paths.
- **Temp Files & Ring Locks**: SQLite WAL ring connections close cleanly upon scope exit.

### D. Honest Audit Row Emission (ADR-0035 §F-2)
- **Invariant COMPLYCLI1**: Every execution path—including invalid commands, failed validations, non-existent entries, and successful mutations—records an explicit audit row via `classify_and_emit` into the security kernel SQLite audit ledger.
- **Audit Row Integrity**: Audit rows contain the precise command name, target ID, status (`success` or `failure`), and sanitized error details.

## 2. Verification
- Verified via `cargo test --manifest-path code/aiosh-rust/Cargo.toml -p aiosh-cli --bin aiosh -- compliance_cli_tests`.
- Zero compiler warnings, 4/4 passing tests.
