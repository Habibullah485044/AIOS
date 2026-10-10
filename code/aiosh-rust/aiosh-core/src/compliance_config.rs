//! Compliance Mapping configuration module (T-02905 SCAFFOLD).
//!
//! Contract: `docs/tasks/evidence/T-02904-spec.md` (normative).
//! Research: `docs/tasks/evidence/T-02903-configuration-research.md`.
//!
//! SCAFFOLD STATUS (T-02905): types, constants, bounds and the `Default`
//! impl are real (serde needs `Default` for `#[serde(default)]`, and the
//! defaults themselves are part of the spec §3.1 contract). Every
//! *behavioral* body is intentionally `unimplemented!("T-02906 …")` and
//! fails loudly — implementation lands in T-02906.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Config file hard cap: 64 KiB (spec §5.1), independent of the 1 MiB
/// store cap. Matches `audit_chain_config.rs`, `capability_config.rs`,
/// `doc_index_config.rs`.
pub const MAX_CONFIG_FILE_BYTES: u64 = 64 * 1024;

/// Default config path (spec §3.2 level 3, T-02903 decision D-2): sits
/// beside the store it configures (`docs/compliance_map.json`).
pub const DEFAULT_CONFIG_PATH: &str = "docs/compliance_config.json";

/// `store_path` override (spec §3.2 level 2).
pub const ENV_COMPLIANCE_CONFIG: &str = "AIOSH_COMPLIANCE_CONFIG";
/// Config-file override env var (spec §3.2 level 2).
pub const ENV_COMPLIANCE_MAP_PATH: &str = "AIOSH_COMPLIANCE_MAP_PATH";

/// `max_store_file_bytes` default / bounds (spec §3.1, §5.2).
pub const DEFAULT_MAX_STORE_FILE_BYTES: u64 = 1024 * 1024; // 1 MiB
pub const MIN_MAX_STORE_FILE_BYTES: u64 = 4096;
pub const MAX_MAX_STORE_FILE_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB

/// `max_entries` default / bounds (spec §3.1, T-02903 decision D-4).
pub const DEFAULT_MAX_ENTRIES: usize = 1024;
pub const MIN_MAX_ENTRIES: usize = 1;
pub const MAX_MAX_ENTRIES: usize = 4096;

/// Longest accepted env/config path value (hygiene predicate, spec §4.3 —
/// byte-for-byte the `threat_model_config.rs:139` rule).
pub const MAX_CONFIG_PATH_LEN: usize = 1024;

// Error codes (spec §4.2). Names are AIOS-specific ⟦AIOS⟧ but follow the
// `THREATCONF_ERR_*` convention already used by `threat_model_config.rs`.
pub const COMPLIANCECONF_ERR_PATH_TRAVERSAL: &str = "COMPLIANCECONF_ERR_PATH_TRAVERSAL";
pub const COMPLIANCECONF_ERR_FILE_SIZE: &str = "COMPLIANCECONF_ERR_FILE_SIZE";
pub const COMPLIANCECONF_ERR_PARSE: &str = "COMPLIANCECONF_ERR_PARSE";
pub const COMPLIANCECONF_ERR_BOUNDS: &str = "COMPLIANCECONF_ERR_BOUNDS";
pub const COMPLIANCECONF_ERR_IO: &str = "COMPLIANCECONF_ERR_IO";
pub const COMPLIANCECONF_ERR_VALIDATION: &str = "COMPLIANCECONF_ERR_VALIDATION";

/// Where a resolved config value came from (spec §3.3 `source` field).
///
/// AIOS-specific ⟦AIOS⟧: no upstream equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    Argument,
    Env,
    File,
    Default,
    /// Env var present but rejected by the hygiene predicate (spec §4.3).
    EnvInvalid,
    /// Config file present but unusable — inert fields clamped/defaulted
    /// per spec §4.2 (fail-closed cases never reach here; they error).
    ConfigInvalid,
}

/// Compliance Mapping configuration (spec §3.1).
///
/// Selects parameters that the *existing* compliance interfaces already
/// accept; it never replaces `validate_path`, the 1 MiB store cap, or the
/// canonical-JSON serializer (spec §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ComplianceConfig {
    pub version: String,
    pub store_path: PathBuf,
    pub max_store_file_bytes: u64,
    pub max_entries: usize,
    pub audit_all_queries: bool,
    /// MUST load as `true` — spec §5.4 rejects `false` so mutation
    /// auditing can never be silently disabled.
    pub audit_all_mutations: bool,
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        ComplianceConfig {
            version: "1.0.0".into(),
            store_path: PathBuf::from(crate::compliance_service::DEFAULT_COMPLIANCE_MAP_PATH),
            max_store_file_bytes: DEFAULT_MAX_STORE_FILE_BYTES,
            max_entries: DEFAULT_MAX_ENTRIES,
            audit_all_queries: false,
            audit_all_mutations: true,
        }
    }
}

/// A resolved config plus the origin of each value (spec §3.3, §4.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedConfig {
    pub config: ComplianceConfig,
    pub source: std::collections::BTreeMap<String, ConfigSource>,
}

impl ComplianceConfig {
    /// Parse from a JSON document, then validate. (spec §4.2 —
    /// malformed JSON is `COMPLIANCECONF_ERR_PARSE` and fails closed.)
    pub fn from_json(json_str: &str) -> Result<Self, String> {
        let config: ComplianceConfig = serde_json::from_str(json_str)
            .map_err(|e| format!("{}: {}", COMPLIANCECONF_ERR_PARSE, e))?;
        let config = config.clamped();
        config.validate()?;
        Ok(config)
    }

    /// Serialize to pretty JSON after validation.
    pub fn to_json(&self) -> Result<String, String> {
        self.validate()?;
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("{}: {}", COMPLIANCECONF_ERR_IO, e))
    }

    /// Read from a path with the 64 KiB cap (spec §5.1) applied *before*
    /// parsing (CWE-400). A missing file yields the defaults (spec §4.2
    /// last row — not an error).
    pub fn from_path(path: &PathBuf) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("{}: {}", COMPLIANCECONF_ERR_IO, e))?;
        if meta.is_dir() {
            return Err(format!(
                "{}: path is a directory: {}",
                COMPLIANCECONF_ERR_IO,
                path.display()
            ));
        }
        if meta.len() > MAX_CONFIG_FILE_BYTES {
            return Err(format!(
                "{}: config file {} is {} bytes, limit {}",
                COMPLIANCECONF_ERR_FILE_SIZE,
                path.display(),
                meta.len(),
                MAX_CONFIG_FILE_BYTES
            ));
        }
        let mut file = std::fs::File::open(path)
            .map_err(|e| format!("{}: {}", COMPLIANCECONF_ERR_IO, e))?;
        use std::io::Read;
        let mut content = String::new();
        file.by_ref()
            .take(MAX_CONFIG_FILE_BYTES)
            .read_to_string(&mut content)
            .map_err(|e| format!("{}: {}", COMPLIANCECONF_ERR_IO, e))?;
        let config: ComplianceConfig = serde_json::from_str(&content)
            .map_err(|e| format!("{}: {}", COMPLIANCECONF_ERR_PARSE, e))?;
        let config = config.clamped();
        config.validate()?;
        Ok(config)
    }

    /// Precedence ladder level 3→4 (spec §3.2): env path if it passes the
    /// hygiene predicate, else default path if it exists, else defaults.
    /// Never panics on bad input (T-02903 F-7 precedent).
    pub fn from_env() -> Result<Self, String> {
        if let Ok(env_path) = std::env::var(ENV_COMPLIANCE_CONFIG) {
            if Self::hygiene_ok(&env_path) && std::path::Path::new(&env_path).exists() {
                if let Ok(c) = Self::from_path(&PathBuf::from(&env_path)) {
                    return Ok(c);
                }
            }
            return Ok(Self::default());
        }
        let default_p = PathBuf::from(DEFAULT_CONFIG_PATH);
        if default_p.exists() {
            if let Ok(c) = Self::from_path(&default_p) {
                return Ok(c);
            }
        }
        Ok(Self::default())
    }

    /// Full 4-level resolution: argument → env → file → default
    /// (spec §3.2), reporting a per-key `source` map (spec §3.3, §4.1).
    pub fn resolve(
        arg_path: Option<&str>,
        arg_config: Option<&str>,
    ) -> Result<ResolvedConfig, String> {
        let mut config = ComplianceConfig::default();
        let mut source: std::collections::BTreeMap<String, ConfigSource> =
            ComplianceConfig::default()
                .field_names()
                .iter()
                .map(|f| (f.to_string(), ConfigSource::Default))
                .collect();

        // Level 3: config file. Explicit --config beats the env var; a
        // file present but unusable fails closed (spec §4.2).
        let file_config = match arg_config {
            Some(p) => {
                if Self::hygiene_ok(p) {
                    Some(Self::from_path(&PathBuf::from(p))?)
                } else {
                    None
                }
            }
            None => match std::env::var(ENV_COMPLIANCE_CONFIG) {
                Ok(env_cfg) if Self::hygiene_ok(&env_cfg) => {
                    Some(Self::from_path(&PathBuf::from(env_cfg))?)
                }
                _ => {
                    let default_p = PathBuf::from(DEFAULT_CONFIG_PATH);
                    if default_p.exists() {
                        Some(Self::from_path(&default_p)?)
                    } else {
                        None
                    }
                }
            },
        };
        if let Some(f) = file_config {
            let defaults = ComplianceConfig::default();
            if f.store_path != defaults.store_path {
                config.store_path = f.store_path.clone();
                source.insert("store_path".into(), ConfigSource::File);
            }
            if f.max_store_file_bytes != defaults.max_store_file_bytes {
                config.max_store_file_bytes = f.max_store_file_bytes;
                source.insert("max_store_file_bytes".into(), ConfigSource::File);
            }
            if f.max_entries != defaults.max_entries {
                config.max_entries = f.max_entries;
                source.insert("max_entries".into(), ConfigSource::File);
            }
            if f.audit_all_queries != defaults.audit_all_queries {
                config.audit_all_queries = f.audit_all_queries;
                source.insert("audit_all_queries".into(), ConfigSource::File);
            }
            if f.audit_all_mutations != defaults.audit_all_mutations {
                config.audit_all_mutations = f.audit_all_mutations;
                source.insert("audit_all_mutations".into(), ConfigSource::File);
            }
            if f.version != defaults.version {
                config.version = f.version.clone();
                source.insert("version".into(), ConfigSource::File);
            }
        }

        // Level 2: env store-path override (CWE-15 hygiene gate).
        if let Ok(raw_store) = std::env::var(ENV_COMPLIANCE_MAP_PATH) {
            if Self::hygiene_ok(&raw_store) {
                config.store_path = PathBuf::from(&raw_store);
                source.insert("store_path".into(), ConfigSource::Env);
            } else {
                source.insert("store_path".into(), ConfigSource::EnvInvalid);
            }
        }

        // Level 1: explicit argument (strongest). Applied unconditionally:
        // an operator-supplied `--path` must NOT be silently replaced by the
        // default when it is invalid — it flows to `validate_path`, which
        // rejects it loudly (exit 2). The hygiene gate exists for *env*
        // values (CWE-15, spec §4.3), not for explicit operator intent.
        if let Some(p) = arg_path {
            config.store_path = PathBuf::from(p);
            source.insert("store_path".into(), ConfigSource::Argument);
        }

        config = config.clamped();
        config.validate()?;
        Ok(ResolvedConfig { config, source })
    }

    /// Field names, for building the default `source` map.
    fn field_names(&self) -> [&'static str; 6] {
        [
            "version",
            "store_path",
            "max_store_file_bytes",
            "max_entries",
            "audit_all_queries",
            "audit_all_mutations",
        ]
    }

    /// Clamp inert numeric fields to their declared bounds (spec §4.2:
    /// "out of bounds -> clamp"). `audit_all_mutations` is forced `true`
    /// (spec §5.4) — config can never disable mutation auditing.
    pub fn clamped(&self) -> Self {
        let mut c = self.clone();
        c.max_entries = c.max_entries.clamp(MIN_MAX_ENTRIES, MAX_MAX_ENTRIES);
        c.max_store_file_bytes =
            c.max_store_file_bytes.clamp(MIN_MAX_STORE_FILE_BYTES, MAX_MAX_STORE_FILE_BYTES);
        c.audit_all_mutations = true;
        if c.version.trim().is_empty() {
            c.version = ComplianceConfig::default().version;
        }
        if c.store_path.as_os_str().is_empty() {
            c.store_path = ComplianceConfig::default().store_path;
        }
        c
    }

    /// Bounds + hygiene validation (spec §3.1 bounds, §5 constraints).
    ///
    /// Fail-closed checks only — inert fields are clamped by `clamped()`.
    pub fn validate(&self) -> Result<(), String> {
        if self.version.trim().is_empty() {
            return Err(format!(
                "{}: 'version' must not be empty",
                COMPLIANCECONF_ERR_VALIDATION
            ));
        }
        if self.store_path.as_os_str().is_empty() {
            return Err(format!(
                "{}: 'store_path' must not be empty",
                COMPLIANCECONF_ERR_VALIDATION
            ));
        }
        Ok(())
    }

    /// Apply the hygiene predicate from spec §4.3 (non-empty, no `..`,
    /// no control chars, `len <= MAX_CONFIG_PATH_LEN`) — the CWE-15 gate
    /// for env-supplied paths.
    pub fn hygiene_ok(value: &str) -> bool {
        let v = value.trim();
        if v.is_empty() {
            return false;
        }
        if v.chars().count() > MAX_CONFIG_PATH_LEN {
            return false;
        }
        if v.contains("..") {
            return false;
        }
        if v.chars().any(|c| c.is_control()) {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-02905 scaffold stub: proves the interface is wired (compiles,
    // links, defaults match spec §3.1). Replaced by behavioral tests in
    // T-02906/T-02907.
    #[test]
    fn test_scaffold_defaults_match_spec_3_1() {
        let c = ComplianceConfig::default();
        assert_eq!(c.version, "1.0.0");
        assert_eq!(
            c.store_path,
            PathBuf::from(crate::compliance_service::DEFAULT_COMPLIANCE_MAP_PATH)
        );
        assert_eq!(c.max_store_file_bytes, 1024 * 1024);
        assert_eq!(c.max_entries, 1024);
        assert!(!c.audit_all_queries);
        // spec §5.4: must default to true, never false.
        assert!(c.audit_all_mutations);
    }

    #[test]
    fn test_scaffold_constants_match_spec() {
        assert_eq!(MAX_CONFIG_FILE_BYTES, 64 * 1024);
        assert_eq!(DEFAULT_CONFIG_PATH, "docs/compliance_config.json");
        assert_eq!(ENV_COMPLIANCE_MAP_PATH, "AIOSH_COMPLIANCE_MAP_PATH");
        assert_eq!(DEFAULT_MAX_ENTRIES, 1024);
        assert_eq!(MAX_MAX_ENTRIES, 4096);
        assert_eq!(MAX_CONFIG_PATH_LEN, 1024);
    }

    // T-02906: hygiene predicate is the CWE-15 gate (spec §4.3) and is
    // total — never panics.
    #[test]
    fn test_hygiene_predicate_matches_spec_4_3() {
        assert!(ComplianceConfig::hygiene_ok("docs/compliance_map.json"));
        assert!(!ComplianceConfig::hygiene_ok(""));
        assert!(!ComplianceConfig::hygiene_ok("   "));
        assert!(!ComplianceConfig::hygiene_ok("../etc/x.json"));
        assert!(!ComplianceConfig::hygiene_ok("docs/\u{1}x.json"));
        assert!(!ComplianceConfig::hygiene_ok(&"a".repeat(MAX_CONFIG_PATH_LEN + 1)));
    }

    // T-02906: inert fields clamp; audit_all_mutations forced true
    // (spec §4.2 / §5.4).
    #[test]
    fn test_clamped_bounds_and_audit_forced_true() {
        let mut c = ComplianceConfig::default();
        c.max_entries = 999_999;
        c.max_store_file_bytes = 999_999_999;
        c.audit_all_mutations = false;
        let c = c.clamped();
        assert_eq!(c.max_entries, MAX_MAX_ENTRIES);
        assert_eq!(c.max_store_file_bytes, MAX_MAX_STORE_FILE_BYTES);
        assert!(c.audit_all_mutations);

        let mut c = ComplianceConfig::default();
        c.max_entries = 0;
        assert_eq!(c.clamped().max_entries, MIN_MAX_ENTRIES);
    }

    // T-02906: malformed config fails closed with the spec §4.2 code;
    // missing file is not an error (returns defaults).
    #[test]
    fn test_malformed_and_missing_config_paths() {
        let dir = std::env::temp_dir().join("aios_compliance_cfg_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let bad = dir.join("bad.json");
        std::fs::write(&bad, "{not valid json").unwrap();
        let err = ComplianceConfig::from_path(&bad).unwrap_err();
        assert!(err.contains(COMPLIANCECONF_ERR_PARSE), "{}", err);

        let big = dir.join("big.json");
        std::fs::write(&big, vec![b' '; (MAX_CONFIG_FILE_BYTES + 1) as usize]).unwrap();
        let err = ComplianceConfig::from_path(&big).unwrap_err();
        assert!(err.contains(COMPLIANCECONF_ERR_FILE_SIZE), "{}", err);

        let missing = dir.join("absent.json");
        let cfg = ComplianceConfig::from_path(&missing).unwrap();
        assert_eq!(cfg, ComplianceConfig::default());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // T-02906: round-trip through JSON with defaults.
    #[test]
    fn test_json_roundtrip_happy() {
        let original = ComplianceConfig::default();
        let json = original.to_json().unwrap();
        let decoded = ComplianceConfig::from_json(&json).unwrap();
        assert_eq!(original, decoded);
    }
}
