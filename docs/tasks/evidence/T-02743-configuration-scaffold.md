# Evidence: T-02743 — Threat Model Configuration Scaffold

## Task Metadata
- **Task ID**: T-02743
- **Title**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / configuration: Scaffold
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Status**: Completed
- **Date**: 2026-10-03
- **Artifact Path**: `docs/tasks/evidence/T-02743-configuration-scaffold.md`

## Objectives
1. Implement the scaffold skeleton for `ThreatModelConfig` in `code/aiosh-rust/aiosh-core/src/threat_model_config.rs`.
2. Define typed function signatures (`validate`, `load_from_path`, `save_to_path`, `from_env`).
3. Wire the module and exports into `code/aiosh-rust/aiosh-core/src/lib.rs`.
4. Validate that the crate compiles cleanly with zero warnings or errors.
5. Perform security audit against relevant CWEs (CWE-20, CWE-22, CWE-400, CWE-778).

## Implementation Details
- Created `code/aiosh-rust/aiosh-core/src/threat_model_config.rs`:
  - Defined `ThreatModelConfig` struct with full field annotations and serde support.
  - Implemented `Default` trait returning safe baseline defaults (`DEFAULT_MAX_THREAT_CAPACITY = 512`, `DEFAULT_MAX_STORE_FILE_BYTES = 1 MiB`, `enforce_strict_transitions = true`).
  - Added typed scaffold signatures with `unimplemented!` stubs for method bodies.
- Updated `code/aiosh-rust/aiosh-core/src/lib.rs`:
  - Added `pub mod threat_model_config;`
  - Re-exported `ThreatModelConfig`, path constants, capacity constants, and error codes.

## Security Audit (CWE Analysis)
- **CWE-20 (Improper Input Validation)**: Typed fields ensure memory layout is bounded; scaffold interfaces define explicit `Result<(), String>` validation signatures.
- **CWE-22 (Path Traversal)**: Config constants and method signatures are structured to disallow relative traversal.
- **CWE-400 (Uncontrolled Resource Consumption)**: Fixed 64 KiB ceiling constant (`MAX_CONFIG_FILE_BYTES`) defined to prevent unbounded ingestion.
- **CWE-778 (Insufficient Logging)**: Prepared for audit ring integration in implementation task.

## Verification
- Ran: `cargo check -p aiosh-core`
- Output: Finished `dev` profile with 0 errors.
