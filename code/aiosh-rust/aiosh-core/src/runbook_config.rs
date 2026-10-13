//! Incident Response Runbooks configuration module (T-03006).
//!
//! Contract: `docs/SPEC-INCIDENT-RUNBOOK-CONFIG.md`.
//! Research: `docs/tasks/evidence/T-03003-research.md`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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

/// Hygiene check for paths.
pub fn hygiene_ok(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_CONFIG_PATH_LEN || trimmed.contains("..") {
        return false;
    }
    !trimmed.chars().any(|ch| (ch as u32) < 32 || (ch as u32) == 127)
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

fn read_raw_config(path: &Path) -> Result<Option<serde_json::Value>, String> {
    if !path.exists() {
        return Ok(None);
    }
    if path.is_dir() {
        return Err(format!("{}: Config path is a directory: {:?}", RUNBOOKCONF_ERR_IO, path));
    }
    let metadata = std::fs::metadata(path)
        .map_err(|e| format!("{}: Cannot stat {:?}: {}", RUNBOOKCONF_ERR_IO, path, e))?;
    if metadata.len() > MAX_CONFIG_FILE_BYTES {
        return Err(format!("{}: Config file {:?} exceeds maximum {} bytes", RUNBOOKCONF_ERR_FILE_SIZE, path, MAX_CONFIG_FILE_BYTES));
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: Cannot read {:?}: {}", RUNBOOKCONF_ERR_IO, path, e))?;
    let val: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("{}: Malformed JSON in {:?}: {}", RUNBOOKCONF_ERR_PARSE, path, e))?;
    if !val.is_object() {
        return Err(format!("{}: Config root must be a JSON object: {:?}", RUNBOOKCONF_ERR_PARSE, path));
    }
    Ok(Some(val))
}

/// Resolve configuration by evaluating the 4-level precedence ladder.
pub fn resolve_runbook_config(overrides: Option<&RunbookConfigOverrides>) -> Result<RunbookConfig, String> {
    let mut config = RunbookConfig::default();

    // Level 3: Config file
    let target_file_path = if let Some(p) = overrides.and_then(|o| o.config_path.as_deref()) {
        validate_config_path(p)?;
        Some(PathBuf::from(p))
    } else if let Ok(env_path) = std::env::var(ENV_RUNBOOK_CONFIG) {
        if hygiene_ok(&env_path) {
            Some(PathBuf::from(env_path))
        } else {
            None
        }
    } else {
        let def = PathBuf::from(DEFAULT_CONFIG_PATH);
        if def.exists() {
            Some(def)
        } else {
            None
        }
    };

    if let Some(ref path) = target_file_path {
        if let Some(val) = read_raw_config(path)? {
            if let Some(obj) = val.as_object() {
                if let Some(cat) = obj.get("catalog_path").and_then(|v| v.as_str()) {
                    if hygiene_ok(cat) {
                        config.catalog_path = cat.to_string();
                        config.sources.insert("catalog_path".to_string(), ConfigSource::File);
                    } else {
                        config.sources.insert("catalog_path".to_string(), ConfigSource::ConfigInvalid);
                    }
                }
                if let Some(ms) = obj.get("max_active_sessions").and_then(|v| v.as_u64()) {
                    config.max_active_sessions = ms.clamp(MIN_MAX_ACTIVE_SESSIONS as u64, MAX_MAX_ACTIVE_SESSIONS as u64) as u32;
                    config.sources.insert("max_active_sessions".to_string(), ConfigSource::File);
                }
                if let Some(mf) = obj.get("max_catalog_file_bytes").and_then(|v| v.as_u64()) {
                    config.max_catalog_file_bytes = mf.clamp(MIN_MAX_CATALOG_FILE_BYTES, MAX_MAX_CATALOG_FILE_BYTES);
                    config.sources.insert("max_catalog_file_bytes".to_string(), ConfigSource::File);
                }
                if let Some(to) = obj.get("default_step_timeout_seconds").and_then(|v| v.as_u64()) {
                    config.default_step_timeout_seconds = to.clamp(MIN_STEP_TIMEOUT_SECONDS, MAX_STEP_TIMEOUT_SECONDS);
                    config.sources.insert("default_step_timeout_seconds".to_string(), ConfigSource::File);
                }
                if let Some(rc) = obj.get("require_operator_confirmation").and_then(|v| v.as_bool()) {
                    config.require_operator_confirmation = rc;
                    config.sources.insert("require_operator_confirmation".to_string(), ConfigSource::File);
                }
            }
        }
    }

    // Level 2: Environment variables
    if let Ok(env_cat) = std::env::var(ENV_RUNBOOK_CATALOG_PATH) {
        if hygiene_ok(&env_cat) {
            config.catalog_path = env_cat.trim().to_string();
            config.sources.insert("catalog_path".to_string(), ConfigSource::Env);
        } else {
            config.sources.insert("catalog_path".to_string(), ConfigSource::EnvInvalid);
        }
    }

    if let Ok(env_ms) = std::env::var(ENV_RUNBOOK_MAX_SESSIONS) {
        if let Ok(parsed) = env_ms.trim().parse::<u32>() {
            config.max_active_sessions = parsed.clamp(MIN_MAX_ACTIVE_SESSIONS, MAX_MAX_ACTIVE_SESSIONS);
            config.sources.insert("max_active_sessions".to_string(), ConfigSource::Env);
        } else {
            config.sources.insert("max_active_sessions".to_string(), ConfigSource::EnvInvalid);
        }
    }

    if let Ok(env_to) = std::env::var(ENV_RUNBOOK_STEP_TIMEOUT) {
        if let Ok(parsed) = env_to.trim().parse::<u64>() {
            config.default_step_timeout_seconds = parsed.clamp(MIN_STEP_TIMEOUT_SECONDS, MAX_STEP_TIMEOUT_SECONDS);
            config.sources.insert("default_step_timeout_seconds".to_string(), ConfigSource::Env);
        } else {
            config.sources.insert("default_step_timeout_seconds".to_string(), ConfigSource::EnvInvalid);
        }
    }

    if let Ok(env_rc) = std::env::var(ENV_RUNBOOK_REQUIRE_CONFIRMATION) {
        let norm = env_rc.trim().to_lowercase();
        if norm == "1" || norm == "true" || norm == "yes" || norm == "on" {
            config.require_operator_confirmation = true;
            config.sources.insert("require_operator_confirmation".to_string(), ConfigSource::Env);
        } else if norm == "0" || norm == "false" || norm == "no" || norm == "off" {
            config.require_operator_confirmation = false;
            config.sources.insert("require_operator_confirmation".to_string(), ConfigSource::Env);
        } else {
            config.sources.insert("require_operator_confirmation".to_string(), ConfigSource::EnvInvalid);
        }
    }

    // Level 1: Overrides
    if let Some(ov) = overrides {
        if let Some(ref cat) = ov.catalog_path {
            validate_config_path(cat)?;
            config.catalog_path = cat.trim().to_string();
            config.sources.insert("catalog_path".to_string(), ConfigSource::Argument);
        }
        if let Some(ms) = ov.max_active_sessions {
            config.max_active_sessions = ms.clamp(MIN_MAX_ACTIVE_SESSIONS, MAX_MAX_ACTIVE_SESSIONS);
            config.sources.insert("max_active_sessions".to_string(), ConfigSource::Argument);
        }
        if let Some(mf) = ov.max_catalog_file_bytes {
            config.max_catalog_file_bytes = mf.clamp(MIN_MAX_CATALOG_FILE_BYTES, MAX_MAX_CATALOG_FILE_BYTES);
            config.sources.insert("max_catalog_file_bytes".to_string(), ConfigSource::Argument);
        }
        if let Some(to) = ov.default_step_timeout_seconds {
            config.default_step_timeout_seconds = to.clamp(MIN_STEP_TIMEOUT_SECONDS, MAX_STEP_TIMEOUT_SECONDS);
            config.sources.insert("default_step_timeout_seconds".to_string(), ConfigSource::Argument);
        }
        if let Some(rc) = ov.require_operator_confirmation {
            config.require_operator_confirmation = rc;
            config.sources.insert("require_operator_confirmation".to_string(), ConfigSource::Argument);
        }
    }

    Ok(config)
}

/// Standardized result envelope for safe configuration resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeResolvedRunbookConfig {
    pub ok: bool,
    pub error_code: Option<String>,
    pub error: Option<String>,
    pub config: RunbookConfig,
}

/// Safe resolution wrapper that never panics or fails loudly; returns standardized result envelope.
pub fn safe_resolve_runbook_config(overrides: Option<&RunbookConfigOverrides>) -> SafeResolvedRunbookConfig {
    match resolve_runbook_config(overrides) {
        Ok(cfg) => SafeResolvedRunbookConfig {
            ok: true,
            error_code: None,
            error: None,
            config: cfg,
        },
        Err(err) => {
            let code = err.split(':').next().unwrap_or(RUNBOOKCONF_ERR_VALIDATION).trim().to_string();
            SafeResolvedRunbookConfig {
                ok: false,
                error_code: Some(code),
                error: Some(err),
                config: RunbookConfig::default(),
            }
        }
    }
}
