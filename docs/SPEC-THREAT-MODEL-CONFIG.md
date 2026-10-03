# Specification: Threat Model Configuration (SPEC-THREAT-MODEL-CONFIG)

- **Status**: IMPLEMENTED & VERIFIED
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Configuration
- **Binding**: ADR-0035 §D-2, ADR-0036 §B-1
- **Tasks**: T-02741 (Research), T-02742 (Spec), T-02743 (Scaffold), T-02744 (Impl), T-02745 (Unit Test), T-02746 (Integration), T-02747 (Security Review), T-02748 (Hardening), T-02749 (Documentation), T-02750 (Milestone Verification)

## 1. Overview
Defines the configuration architecture, parameters, defaults, and boundary constraints for the Threat Model Maintenance subsystem in `aiosh-core` and its operational exposure via MCP (`aios.threat.config`). It allows system operators and runtime profiles to customize storage locations, capacity caps, validation strictness, and audit verbosity.

## 2. Invariants & Rulesets

| Invariant | Name | Description |
|---|---|---|
| `THREATCONF1` | **Version Conformance** | `version` must be non-empty and start with `"1."`. |
| `THREATCONF2` | **Path Traversal Hygiene** | `store_path` must not contain `..`, UNC paths, control characters, or exceed 1024 bytes. Symlinks are rejected. |
| `THREATCONF3` | **Capacity Ceilings** | `max_threat_capacity` bounded in `[1, 4096]`. Default is 512. |
| `THREATCONF4` | **File Size Ceilings** | `max_store_file_bytes` bounded in `[4096, 16777216]` (4 KiB to 16 MiB). Config file capped at 64 KiB. |
| `THREATCONF5` | **Atomic Persistence** | Writes use temporary files (`tmp.<pid>.<nanos>`) and atomic rename, with strict unlinking on any error. |

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
4. `AIOS_THREAT_MAX_STORE_FILE`: Numerical string override for `max_store_file_bytes`.

## 6. Error Codes
- `THREATCONF_ERR_IO`: Filesystem read/write errors.
- `THREATCONF_ERR_PARSE`: JSON deserialization failures.
- `THREATCONF_ERR_VALIDATION`: Structural invalidity (version, path format, symlink detection).
- `THREATCONF_ERR_BOUNDS`: Numerical boundary violations.

## 7. Working Usage Examples

### 7.1 Inspecting Active Configuration via MCP
```json
{
  "name": "aios.threat.config",
  "arguments": {
    "action": "show"
  }
}
```
**Response:**
```json
{
  "action": "show",
  "config": {
    "audit_all_mutations": true,
    "audit_all_queries": true,
    "enable_private_key_scrubbing": true,
    "enforce_strict_transitions": true,
    "max_store_file_bytes": 1048576,
    "max_threat_capacity": 512,
    "require_mitigation_for_status": true,
    "store_path": "target/threat_model.json",
    "version": "1.0.0"
  },
  "ok": true
}
```

### 7.2 Validating Configuration File via MCP
```json
{
  "name": "aios.threat.config",
  "arguments": {
    "action": "check",
    "config_path": "config/threat_model_config.json"
  }
}
```
**Response:**
```json
{
  "action": "check",
  "ok": true,
  "valid": true
}
```

### 7.3 Programmatic Usage in Rust
```rust
use aiosh_core::threat_model_config::ThreatModelConfig;
use aiosh_core::threat_model_service::ThreatModelService;

// Load defaults or environment overrides
let config = ThreatModelConfig::from_env();
config.validate().expect("Configuration invariants must hold");

// Instantiate service bound to configuration
let service = ThreatModelService::from_config(&config);
```

## 8. Constraints & Known Limitations
1. **Dynamic Reload**: In-memory `ThreatModelService` instances do not hot-reload file modifications; services must be re-instantiated upon external configuration edits.
2. **Symlinks Not Supported**: Configuration files cannot be symbolic links (CWE-59 mitigation).
3. **Single Store File Limit**: Catalog storage is backed by a single JSON document up to 16 MiB; distributed sharding across multi-file backends is not supported in Phase 2.

## 9. Task Evidence References
- [Research Evidence (T-02741)](evidence/T-02741-configuration-research.md)
- [Unit Testing Evidence (T-02745)](evidence/T-02745-completion.md)
- [Security Review (T-02747)](evidence/T-02747-configuration-security-review.md)
- [Hardening Evidence (T-02748)](evidence/T-02748-configuration-hardening.md)
