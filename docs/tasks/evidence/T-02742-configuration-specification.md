# Specification: Threat Model Configuration (T-02742)

## Task Metadata
- **Task ID**: T-02742
- **Title**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / configuration: Specification
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Status**: Completed
- **Date**: 2026-10-03
- **Artifact Path**: `docs/tasks/evidence/T-02742-configuration-specification.md`

## 1. Specification Contract
This specification establishes the interface and behavior contract for `ThreatModelConfig` in `code/aiosh-rust/aiosh-core/src/threat_model_config.rs`.

Full specification published at: [`docs/SPEC-THREAT-MODEL-CONFIG.md`](file:///c:/Users/OBSESSION/Desktop/AIOS_MERGED/docs/SPEC-THREAT-MODEL-CONFIG.md).

## 2. Interface Definitions & Contracts

### Struct `ThreatModelConfig`
- `version: String`
- `store_path: PathBuf`
- `max_threat_capacity: usize`
- `max_store_file_bytes: u64`
- `enforce_strict_transitions: bool`
- `require_mitigation_for_status: bool`
- `enable_private_key_scrubbing: bool`
- `audit_all_queries: bool`
- `audit_all_mutations: bool`

### Methods
- `default() -> Self`
- `validate(&self) -> Result<(), String>`
- `load_from_path<P: AsRef<Path>>(path: P) -> Result<Self, String>`
- `save_to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), String>`
- `from_env() -> Self`

## 3. Invariants & Bounds
- `THREATCONF1`: Version prefix `"1."`.
- `THREATCONF2`: Rejection of `..`, UNC paths, control characters, max path length 1024 bytes.
- `THREATCONF3`: `max_threat_capacity` bounded in `[1, 4096]`.
- `THREATCONF4`: `max_store_file_bytes` bounded in `[4096, 16777216]` (4 KiB to 16 MiB). Config file max 64 KiB.
- `THREATCONF5`: Atomic write with temp file cleanup on error.

## 4. Security Audit (CWE Analysis)
- **CWE-20 (Improper Input Validation)**: All fields undergo structural and numerical boundary validation in `validate()`.
- **CWE-22 (Path Traversal)**: Traversal sequences in both configuration and store paths are rejected.
- **CWE-400 (Uncontrolled Resource Consumption)**: Fixed 64 KiB ceiling on config file ingestion prevents memory exhaustion.
- **CWE-778 (Insufficient Logging)**: Config load/save actions are logged when executed through system services.
