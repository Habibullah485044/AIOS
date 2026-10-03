//! Threat Model Configuration Subsystem (T-02741..T-02750).
//!
//! Governs runtime parameters, capacity ceilings, file paths, and security constraints
//! for threat model catalog management in `aiosh-core`.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_THREAT_CONFIG_PATH: &str = ".aios/threat_model_config.json";
pub const DEFAULT_THREAT_STORE_PATH: &str = "target/threat_model.json";

pub const DEFAULT_MAX_THREAT_CAPACITY: usize = 512;
pub const MIN_MAX_THREAT_CAPACITY: usize = 1;
pub const MAX_MAX_THREAT_CAPACITY: usize = 4096;

pub const DEFAULT_MAX_STORE_FILE_BYTES: u64 = 1048576; // 1 MiB
pub const MIN_MAX_STORE_FILE_BYTES: u64 = 4096; // 4 KiB
pub const MAX_MAX_STORE_FILE_BYTES: u64 = 16777216; // 16 MiB

pub const MAX_CONFIG_FILE_BYTES: u64 = 65536; // 64 KiB

pub const THREATCONF_ERR_IO: &str = "THREATCONF_ERR_IO";
pub const THREATCONF_ERR_PARSE: &str = "THREATCONF_ERR_PARSE";
pub const THREATCONF_ERR_VALIDATION: &str = "THREATCONF_ERR_VALIDATION";
pub const THREATCONF_ERR_BOUNDS: &str = "THREATCONF_ERR_BOUNDS";

/// Configuration settings for the Threat Model Maintenance subsystem.
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

impl Default for ThreatModelConfig {
    fn default() -> Self {
        Self {
            version: "1.0.0".into(),
            store_path: PathBuf::from(DEFAULT_THREAT_STORE_PATH),
            max_threat_capacity: DEFAULT_MAX_THREAT_CAPACITY,
            max_store_file_bytes: DEFAULT_MAX_STORE_FILE_BYTES,
            enforce_strict_transitions: true,
            require_mitigation_for_status: true,
            enable_private_key_scrubbing: true,
            audit_all_queries: true,
            audit_all_mutations: true,
        }
    }
}

impl ThreatModelConfig {
    /// Validates structural invariants and numerical boundaries.
    pub fn validate(&self) -> Result<(), String> {
        if self.version.is_empty() || !self.version.starts_with("1.") {
            return Err(format!("{}: invalid version '{}'", THREATCONF_ERR_VALIDATION, self.version));
        }
        let store_str = self.store_path.to_string_lossy();
        if store_str.trim().is_empty() {
            return Err(format!("{}: store_path cannot be empty", THREATCONF_ERR_VALIDATION));
        }
        if store_str.contains("..") {
            return Err(format!("{}: store_path cannot contain directory traversal '..'", THREATCONF_ERR_VALIDATION));
        }
        if store_str.chars().any(|c| c.is_control()) || store_str.len() > 1024 {
            return Err(format!("{}: store_path contains invalid control characters or exceeds 1024 bytes", THREATCONF_ERR_VALIDATION));
        }
        if self.max_threat_capacity < MIN_MAX_THREAT_CAPACITY || self.max_threat_capacity > MAX_MAX_THREAT_CAPACITY {
            return Err(format!(
                "{}: max_threat_capacity {} out of bounds ({}..{})",
                THREATCONF_ERR_BOUNDS, self.max_threat_capacity, MIN_MAX_THREAT_CAPACITY, MAX_MAX_THREAT_CAPACITY
            ));
        }
        if self.max_store_file_bytes < MIN_MAX_STORE_FILE_BYTES || self.max_store_file_bytes > MAX_MAX_STORE_FILE_BYTES {
            return Err(format!(
                "{}: max_store_file_bytes {} out of bounds ({}..{})",
                THREATCONF_ERR_BOUNDS, self.max_store_file_bytes, MIN_MAX_STORE_FILE_BYTES, MAX_MAX_STORE_FILE_BYTES
            ));
        }
        Ok(())
    }

    /// Loads configuration from a JSON file path with bounds checking.
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let p = path.as_ref();
        let meta = std::fs::symlink_metadata(p)
            .map_err(|e| format!("{}: cannot stat {:?}: {}", THREATCONF_ERR_IO, p, e))?;
        if meta.file_type().is_symlink() {
            return Err(format!("{}: symlinks rejected for config files", THREATCONF_ERR_VALIDATION));
        }
        if meta.len() > MAX_CONFIG_FILE_BYTES {
            return Err(format!("{}: config file size {} exceeds max {}", THREATCONF_ERR_BOUNDS, meta.len(), MAX_CONFIG_FILE_BYTES));
        }
        let data = std::fs::read_to_string(p)
            .map_err(|e| format!("{}: cannot read {:?}: {}", THREATCONF_ERR_IO, p, e))?;
        let config: Self = serde_json::from_str(&data)
            .map_err(|e| format!("{}: invalid JSON in {:?}: {}", THREATCONF_ERR_PARSE, p, e))?;
        config.validate()?;
        Ok(config)
    }

    /// Atomically saves configuration to a JSON file with zero temp-leak guarantees.
    pub fn save_to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        self.validate()?;
        let p = path.as_ref();
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("{}: cannot create directory {:?}: {}", THREATCONF_ERR_IO, parent, e))?;
            }
        }
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| format!("{}: serialization failed: {}", THREATCONF_ERR_PARSE, e))?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let temp_path = p.with_extension(format!("tmp.{}.{}", std::process::id(), nanos));
        if let Err(e) = std::fs::write(&temp_path, &data) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(format!("{}: failed writing tempfile: {}", THREATCONF_ERR_IO, e));
        }
        std::fs::rename(&temp_path, p).map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            format!("{}: failed renaming to {:?}: {}", THREATCONF_ERR_IO, p, e)
        })?;
        Ok(())
    }

    /// Loads configuration with environment variable overrides.
    pub fn from_env() -> Self {
        let mut config = if let Ok(custom_path_raw) = std::env::var("AIOS_THREAT_MODEL_CONFIG") {
            let custom_path = custom_path_raw.trim();
            if !custom_path.is_empty() && !custom_path.contains("..") && !custom_path.chars().any(|c| c.is_control()) && custom_path.len() <= 1024 {
                Self::load_from_path(custom_path).unwrap_or_default()
            } else {
                Self::default()
            }
        } else if Path::new(DEFAULT_THREAT_CONFIG_PATH).exists() {
            Self::load_from_path(DEFAULT_THREAT_CONFIG_PATH).unwrap_or_default()
        } else {
            Self::default()
        };

        if let Ok(store_raw) = std::env::var("AIOS_THREAT_MODEL_PATH") {
            let store = store_raw.trim();
            if !store.is_empty() && !store.contains("..") && !store.chars().any(|c| c.is_control()) && store.len() <= 1024 {
                config.store_path = PathBuf::from(store);
            }
        }
        if let Ok(cap_str) = std::env::var("AIOS_THREAT_CAPACITY") {
            if let Ok(cap) = cap_str.trim().parse::<usize>() {
                if (MIN_MAX_THREAT_CAPACITY..=MAX_MAX_THREAT_CAPACITY).contains(&cap) {
                    config.max_threat_capacity = cap;
                }
            }
        }
        if let Ok(file_size_str) = std::env::var("AIOS_THREAT_MAX_STORE_FILE") {
            if let Ok(fsz) = file_size_str.trim().parse::<u64>() {
                if (MIN_MAX_STORE_FILE_BYTES..=MAX_MAX_STORE_FILE_BYTES).contains(&fsz) {
                    config.max_store_file_bytes = fsz;
                }
            }
        }
        config
    }
}
