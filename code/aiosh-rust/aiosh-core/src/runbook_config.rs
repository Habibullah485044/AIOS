//! Incident Response Runbooks configuration module (T-03005 SCAFFOLD).
//!
//! Contract: `docs/SPEC-INCIDENT-RUNBOOK-CONFIG.md`.
//! Research: `docs/tasks/evidence/T-03003-research.md`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Hard cap on configuration JSON file: 64 KiB.
pub const MAX_CONFIG_FILE_BYTES: u64 = 64 * 1024;

/// Default path to runbook configuration JSON file.
pub const DEFAULT_CONFIG_PATH: &str = "docs/runbook_config.json";

/// Default path to runbook catalog store.
pub const DEFAULT_CATALOG_PATH: &str = "docs/runbook_catalog.json";

/// Environment variable overrides.
pub const ENV_RUNBOOK_CONFIG: &str = "AIOSH_RUNBOOK_CONFIG";
pub const ENV_RUNBOOK_CATALOG_PATH: &str = "AIOSH_RUNBOOK_CATALOG_PATH";
pub const ENV_RUNBOOK_MAX_SESSIONS: &str = "AIOSH_RUNBOOK_MAX_SESSIONS";
pub const ENV_RUNBOOK_STEP_TIMEOUT: &str = "AIOSH_RUNBOOK_STEP_TIMEOUT";
pub const ENV_RUNBOOK_REQUIRE_CONFIRMATION: &str = "AIOSH_RUNBOOK_REQUIRE_CONFIRMATION";

/// Defaults and boundary clamping constants.
pub const DEFAULT_MAX_ACTIVE_SESSIONS: u32 = 1000;
pub const MIN_MAX_ACTIVE_SESSIONS: u32 = 1;
pub const MAX_MAX_ACTIVE_SESSIONS: u32 = 10000;

pub const DEFAULT_MAX_CATALOG_FILE_BYTES: u64 = 1024 * 1024; // 1 MiB
pub const MIN_MAX_CATALOG_FILE_BYTES: u64 = 4096;
pub const MAX_MAX_CATALOG_FILE_BYTES: u64 = 16 * 1024 * 1024; // 16 MiB

pub const DEFAULT_STEP_TIMEOUT_SECONDS: u64 = 3600; // 1 hour
pub const MIN_STEP_TIMEOUT_SECONDS: u64 = 1;
pub const MAX_STEP_TIMEOUT_SECONDS: u64 = 86400; // 24 hours

pub const MAX_CONFIG_PATH_LEN: usize = 1024;

/// Standardized error codes.
pub const RUNBOOKCONF_ERR_PATH_TRAVERSAL: &str = "RUNBOOKCONF_ERR_PATH_TRAVERSAL";
pub const RUNBOOKCONF_ERR_FILE_SIZE: &str = "RUNBOOKCONF_ERR_FILE_SIZE";
pub const RUNBOOKCONF_ERR_PARSE: &str = "RUNBOOKCONF_ERR_PARSE";
pub const RUNBOOKCONF_ERR_BOUNDS: &str = "RUNBOOKCONF_ERR_BOUNDS";
pub const RUNBOOKCONF_ERR_IO: &str = "RUNBOOKCONF_ERR_IO";
pub const RUNBOOKCONF_ERR_VALIDATION: &str = "RUNBOOKCONF_ERR_VALIDATION";

/// Configuration field source provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    Argument,
    Env,
    File,
    Default,
    EnvInvalid,
    ConfigInvalid,
}

impl ConfigSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConfigSource::Argument => "argument",
            ConfigSource::Env => "env",
            ConfigSource::File => "file",
            ConfigSource::Default => "default",
            ConfigSource::EnvInvalid => "env_invalid",
            ConfigSource::ConfigInvalid => "config_invalid",
        }
    }
}

/// Resolved Incident Response Runbooks configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookConfig {
    pub catalog_path: String,
    pub max_active_sessions: u32,
    pub max_catalog_file_bytes: u64,
    pub default_step_timeout_seconds: u64,
    pub require_operator_confirmation: bool,
    pub sources: HashMap<String, ConfigSource>,
}

impl Default for RunbookConfig {
    fn default() -> Self {
        let mut sources = HashMap::new();
        sources.insert("catalog_path".to_string(), ConfigSource::Default);
        sources.insert("max_active_sessions".to_string(), ConfigSource::Default);
        sources.insert("max_catalog_file_bytes".to_string(), ConfigSource::Default);
        sources.insert("default_step_timeout_seconds".to_string(), ConfigSource::Default);
        sources.insert("require_operator_confirmation".to_string(), ConfigSource::Default);

        Self {
            catalog_path: DEFAULT_CATALOG_PATH.to_string(),
            max_active_sessions: DEFAULT_MAX_ACTIVE_SESSIONS,
            max_catalog_file_bytes: DEFAULT_MAX_CATALOG_FILE_BYTES,
            default_step_timeout_seconds: DEFAULT_STEP_TIMEOUT_SECONDS,
            require_operator_confirmation: true,
            sources,
        }
    }
}

/// Caller overrides for configuration resolution.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookConfigOverrides {
    pub config_path: Option<String>,
    pub catalog_path: Option<String>,
    pub max_active_sessions: Option<u32>,
    pub max_catalog_file_bytes: Option<u64>,
    pub default_step_timeout_seconds: Option<u64>,
    pub require_operator_confirmation: Option<bool>,
}

/// Resolve configuration by evaluating the 4-level precedence ladder.
/// Scaffold implementation fails loudly with unimplemented.
pub fn resolve_runbook_config(_overrides: Option<&RunbookConfigOverrides>) -> Result<RunbookConfig, String> {
    unimplemented!("resolve_runbook_config scaffold - pending T-03006 implementation")
}

/// Validate configuration path against traversal and length limits.
pub fn validate_config_path(path: &str) -> Result<PathBuf, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(format!("{}: Path cannot be empty", RUNBOOKCONF_ERR_VALIDATION));
    }
    if trimmed.len() > MAX_CONFIG_PATH_LEN {
        return Err(format!("{}: Path length {} exceeds maximum {}", RUNBOOKCONF_ERR_BOUNDS, trimmed.len(), MAX_CONFIG_PATH_LEN));
    }
    if trimmed.contains("..") {
        return Err(format!("{}: Path traversal '..' strictly prohibited", RUNBOOKCONF_ERR_PATH_TRAVERSAL));
    }
    Ok(PathBuf::from(trimmed))
}
