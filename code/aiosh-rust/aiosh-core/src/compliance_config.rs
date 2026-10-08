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
    pub fn from_json(_json_str: &str) -> Result<Self, String> {
        unimplemented!("T-02906: ComplianceConfig::from_json")
    }

    /// Serialize to pretty JSON after validation.
    pub fn to_json(&self) -> Result<String, String> {
        unimplemented!("T-02906: ComplianceConfig::to_json")
    }

    /// Read from a path with the 64 KiB cap (spec §5.1) applied *before*
    /// parsing (CWE-400).
    pub fn from_path(_path: &PathBuf) -> Result<Self, String> {
        unimplemented!("T-02906: ComplianceConfig::from_path")
    }

    /// Precedence ladder level 3→4 (spec §3.2): env path if it passes the
    /// hygiene predicate, else default path if it exists, else defaults.
    /// Never panics on bad input (T-02903 F-7 precedent).
    pub fn from_env() -> Result<Self, String> {
        unimplemented!("T-02906: ComplianceConfig::from_env")
    }

    /// Full 4-level resolution: argument → env → file → default
    /// (spec §3.2), reporting a per-key `source` map (spec §3.3, §4.1).
    ///
    /// `arg_path` is the CLI `--path` value (strongest override);
    /// `arg_config` is the CLI `--config` value.
    pub fn resolve(
        _arg_path: Option<&str>,
        _arg_config: Option<&str>,
    ) -> Result<ResolvedConfig, String> {
        unimplemented!("T-02906: ComplianceConfig::resolve")
    }

    /// Bounds + hygiene validation (spec §3.1 bounds, §5 constraints).
    ///
    /// Inert fields clamp, security-relevant fields fail closed
    /// (spec §4.2 — T-02903 decision D-5).
    pub fn validate(&self) -> Result<(), String> {
        unimplemented!("T-02906: ComplianceConfig::validate")
    }

    /// Apply the hygiene predicate from spec §4.3 (non-empty, no `..`,
    /// no control chars, `len <= MAX_CONFIG_PATH_LEN`) — the CWE-15 gate
    /// for env-supplied paths.
    pub fn hygiene_ok(_value: &str) -> bool {
        unimplemented!("T-02906: ComplianceConfig::hygiene_ok")
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

    // Scaffold: behavioral bodies must fail loudly until T-02906.
    #[test]
    #[should_panic(expected = "T-02906")]
    fn test_scaffold_unimplemented_fails_loudly() {
        let _ = ComplianceConfig::from_env();
    }
}
