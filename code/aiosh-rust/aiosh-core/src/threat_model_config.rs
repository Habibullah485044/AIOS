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
    pub fn validate(&self) -> Result<(), String> {
        unimplemented!("T-02743 scaffold: ThreatModelConfig::validate")
    }

    pub fn load_from_path<P: AsRef<Path>>(_path: P) -> Result<Self, String> {
        unimplemented!("T-02743 scaffold: ThreatModelConfig::load_from_path")
    }

    pub fn save_to_path<P: AsRef<Path>>(&self, _path: P) -> Result<(), String> {
        unimplemented!("T-02743 scaffold: ThreatModelConfig::save_to_path")
    }

    pub fn from_env() -> Self {
        unimplemented!("T-02743 scaffold: ThreatModelConfig::from_env")
    }
}
