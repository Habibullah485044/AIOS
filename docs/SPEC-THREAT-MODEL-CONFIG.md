# Specification: Threat Model Configuration (SPEC-THREAT-MODEL-CONFIG)

- **Status**: SPECIFIED
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Configuration
- **Binding**: ADR-0035 §D-2, ADR-0036 §B-1

## 1. Overview
Defines the configuration architecture, parameters, defaults, and boundary constraints for the Threat Model Maintenance subsystem in `aiosh-core`. It allows system operators and runtime profiles to customize storage locations, capacity caps, validation strictness, and audit verbosity.

## 2. Invariants & Rulesets

| Invariant | Name | Description |
|---|---|---|
| `THREATCONF1` | **Version Conformance** | `version` must be non-empty and start with `"1."`. |
| `THREATCONF2` | **Path Traversal Hygiene** | `store_path` must not contain `..`, UNC paths, control characters, or exceed 1024 bytes. |
| `THREATCONF3` | **Capacity Ceilings** | `max_threat_capacity` bounded in `[1, 4096]`. |
| `THREATCONF4` | **File Size Ceilings** | `max_store_file_bytes` bounded in `[4096, 16777216]` (4 KiB to 16 MiB). Config file capped at 64 KiB. |
| `THREATCONF5` | **Atomic Persistence** | Writes use temporary files (`.threat_conf.tmp.<pid>.<nanos>`) and atomic rename, cleaning up on any error. |

## 3. Data Structure

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

## 4. Default Values
- `version`: `"1.0.0"`
- `store_path`: `"target/threat_model.json"`
- `max_threat_capacity`: `512`
- `max_store_file_bytes`: `1048576` (1 MiB)
- `enforce_strict_transitions`: `true`
- `require_mitigation_for_status`: `true`
- `enable_private_key_scrubbing`: `true`
- `audit_all_queries`: `true`
- `audit_all_mutations`: `true`

## 5. Environment Variables & Fallback Cascades
1. `AIOS_THREAT_MODEL_CONFIG`: Custom path to configuration file (defaults to `.aios/threat_model_config.json`).
2. `AIOS_THREAT_MODEL_PATH`: Overrides `store_path`.
3. `AIOS_THREAT_CAPACITY`: Numerical string override for `max_threat_capacity`.

## 6. Error Codes
- `THREATCONF_ERR_IO`: Filesystem read/write errors.
- `THREATCONF_ERR_PARSE`: JSON deserialization failures.
- `THREATCONF_ERR_VALIDATION`: Structural invalidity (version, path format).
- `THREATCONF_ERR_BOUNDS`: Numerical boundary violations.
