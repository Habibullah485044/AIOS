# Research: Threat Model Maintenance Configuration (T-02741)

## Task Metadata
- **Task ID**: T-02741
- **Title**: Phase 2 — Security Kernel & PEP Fabric / Threat Model Maintenance / configuration: Research
- **Phase**: Phase 2 — Security Kernel & PEP Fabric
- **Status**: Completed
- **Date**: 2026-10-03
- **Artifact Path**: `docs/tasks/evidence/T-02741-configuration-research.md`

## 1. Executive Summary
This research document establishes facts, constraints, and prior art for configuring the Threat Model Maintenance subsystem (`Sub-Epic 5`, `T-02741` – `T-02750`). It defines the architecture for `ThreatModelConfig`, runtime parameter resolution (defaults, config files, and environment variable overrides), memory boundaries, path safety barriers, and audit synchronization.

## 2. Established Facts vs Assumptions

### Established Facts
1. **Existing Config Implementations in `aiosh-core`**:
   - `SecretConfig` (`code/aiosh-rust/aiosh-core/src/secret_config.rs`)
   - `PrivilegeConfig` (`code/aiosh-rust/aiosh-core/src/privilege_config.rs`)
   - `SandboxConfig` (`code/aiosh-rust/aiosh-core/src/sandbox_config.rs`)
   - `PepConfig` (`code/aiosh-rust/aiosh-core/src/pep_config.rs`)
   - These modules establish the precedent: strongly-typed structs serializable to canonical JSON, strict boundary bounds (`MIN_..` to `MAX_..`), path traversal checks (`..`, control characters), atomic writes via PID-tagged temp files, and `from_env()` fallback cascades.
2. **Hard System Limits in Threat Model Subsystem**:
   - `MAX_THREAT_MODEL_STORE_SIZE = 1_048_576` (1 MiB).
   - `MAX_THREAT_ENTRIES_CAPACITY = 512` entries.
   - String limits: ID <= 64, Title <= 128, Description <= 2048, Mitigation <= 1024.
3. **Environment Variable Precedence**:
   - `AIOS_THREAT_MODEL_CONFIG`: Custom path to `threat_model_config.json`.
   - `AIOS_THREAT_MODEL_PATH`: Custom path to `threat_model.json`.
   - `AIOS_THREAT_CAPACITY`: Numerical override for maximum catalog capacity.
   - Default config file path: `.aios/threat_model_config.json`.
   - Default store path: `target/threat_model.json`.

### Assumptions
1. **Assumption A-1**: Operators may want to adjust capacity dynamically between 1 and 4096 threats without recompiling code.
   - *Validation*: Supported via `max_threat_capacity` with hard bounds `[1, 4096]`.
2. **Assumption A-2**: Configuration loading must never panic or crash the process on malformed input, falling back gracefully to safe defaults or returning typed error envelopes.
   - *Validation*: Confirmed; error constants `THREATCONF_ERR_IO`, `THREATCONF_ERR_PARSE`, `THREATCONF_ERR_VALIDATION`, `THREATCONF_ERR_BOUNDS` will be used.

## 3. Prior Art & Authoritative Sources
1. **ADR-0035 §D-2**: Kernel and service configuration files must be deterministic, auditable, and subject to strict size caps (maximum 64 KiB for config files).
2. **ADR-0036 §B-1**: Configuration files must reside within approved system directories (`.aios/` or isolated target directories), rejecting relative directory traversal escapes (`..`).
3. **NIST SP 800-53 Rev 5 (CM-6, Configuration Settings)**: Mandatory bounds validation and integrity verification of configuration parameters prior to activation.
4. **CWE-15 (External Control of System or Configuration Setting)**: Enforce boundary validation to prevent untrusted environmental tampering.

## 4. Architectural Design for `ThreatModelConfig`

### Data Model
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatModelConfig {
    pub version: String,
    pub store_path: PathBuf,
    pub max_threat_capacity: usize,
    pub max_store_file_bytes: u64,
    pub enforce_strict_transitions: bool,
    pub require_mitigation_for_status: bool,
    pub enable_private_key_scrubbing: bool,
    pub audit_all_queries: bool,
    pub audit_all_mutations: bool,
}
```

### Numerical Boundaries
- `DEFAULT_MAX_THREAT_CAPACITY`: 512 (min: 1, max: 4096)
- `DEFAULT_MAX_STORE_FILE_BYTES`: 1,048,576 (min: 4096, max: 16,777,216)
- `MAX_CONFIG_FILE_BYTES`: 65,536 (64 KiB)

## 5. Security Review & CWE Analysis
- **CWE-20 (Improper Input Validation)**: Config parser must reject out-of-bounds capacity or invalid versions.
- **CWE-22 (Path Traversal)**: Config path and target store paths must reject `..` traversal, UNC paths, control characters, and symlinks.
- **CWE-400 (Uncontrolled Resource Consumption)**: Config file reader is capped at 64 KiB to prevent memory exhaustion via `/dev/urandom` or endless files.

## 6. Open Decisions & Resolution
1. **Decision D-1**: What should happen if `threat_model_config.json` does not exist?
   - *Resolution*: Return `ThreatModelConfig::default()` gracefully in `from_env()`.
2. **Decision D-2**: Should `ThreatModelService` be configurable via `ThreatModelConfig`?
   - *Resolution*: Yes, `ThreatModelService::with_config(config: ThreatModelConfig)` will allow initializing services with custom bounds.
