//! AI Control Plane MCP Server Core Configuration Subsystem (T-03105 scaffold / T-03106 impl).
//!
//! Enforces configuration parameters, resolution hierarchy, and validation invariants
//! MCPCFG-INV1..MCPCFG-INV8 in compliance with SPEC-MCP-SERVER-CORE-CONFIG and PoR Invariant I-2.

use std::path::PathBuf;
use serde::{Deserialize, Serialize};

pub const DEFAULT_STORE_PATH: &str = ".aios/mcp_store.json";
pub const DEFAULT_MAX_ACTIVE_SESSIONS: usize = 64;
pub const DEFAULT_SESSION_IDLE_TIMEOUT: u64 = 3600;
pub const DEFAULT_EXECUTION_TIMEOUT: u64 = 30;
pub const DEFAULT_MAX_ARGUMENTS_SIZE: usize = 1_048_576; // 1 MiB
pub const DEFAULT_MAX_TOOLS_COUNT: usize = 256;
pub const DEFAULT_REQUIRE_ADMIN_GRANT: bool = true;
pub const DEFAULT_AUTO_PRUNE_TERMINATED: bool = true;

pub const MIN_ACTIVE_SESSIONS: usize = 1;
pub const MAX_ALLOWED_ACTIVE_SESSIONS: usize = 512;
pub const MIN_IDLE_TIMEOUT: u64 = 60;
pub const MAX_ALLOWED_IDLE_TIMEOUT: u64 = 86400;
pub const MIN_EXECUTION_TIMEOUT: u64 = 1;
pub const MAX_ALLOWED_EXECUTION_TIMEOUT: u64 = 300;
pub const MIN_ARGUMENTS_SIZE: usize = 1024;
pub const MAX_ALLOWED_ARGUMENTS_SIZE: usize = 10 * 1024 * 1024; // 10 MiB
pub const MIN_TOOLS_COUNT: usize = 1;
pub const MAX_ALLOWED_TOOLS_COUNT: usize = 1024;
pub const MAX_CONFIG_FILE_BYTES: u64 = 65_536; // 64 KiB

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerCoreConfig {
    pub store_path: PathBuf,
    pub max_active_sessions: usize,
    pub session_idle_timeout_seconds: u64,
    pub default_execution_timeout_seconds: u64,
    pub max_arguments_size_bytes: usize,
    pub max_tools_count: usize,
    pub require_admin_grant: bool,
    pub auto_prune_terminated: bool,
}

impl Default for McpServerCoreConfig {
    fn default() -> Self {
        Self {
            store_path: PathBuf::from(DEFAULT_STORE_PATH),
            max_active_sessions: DEFAULT_MAX_ACTIVE_SESSIONS,
            session_idle_timeout_seconds: DEFAULT_SESSION_IDLE_TIMEOUT,
            default_execution_timeout_seconds: DEFAULT_EXECUTION_TIMEOUT,
            max_arguments_size_bytes: DEFAULT_MAX_ARGUMENTS_SIZE,
            max_tools_count: DEFAULT_MAX_TOOLS_COUNT,
            require_admin_grant: DEFAULT_REQUIRE_ADMIN_GRANT,
            auto_prune_terminated: DEFAULT_AUTO_PRUNE_TERMINATED,
        }
    }
}

impl McpServerCoreConfig {
    pub fn validate(&self) -> Result<(), String> {
        let path_str = self.store_path.to_string_lossy();
        if path_str.is_empty() {
            return Err("MCPCFG-INV1 violation: store_path cannot be empty".into());
        }
        if path_str.contains('\0') {
            return Err("MCPCFG-INV1 violation: store_path cannot contain NUL bytes".into());
        }
        for comp in self.store_path.components() {
            if comp.as_os_str() == ".." {
                return Err("MCPCFG-INV1 violation: store_path cannot contain directory traversal ('..')".into());
            }
        }

        if self.max_active_sessions < MIN_ACTIVE_SESSIONS || self.max_active_sessions > MAX_ALLOWED_ACTIVE_SESSIONS {
            return Err(format!(
                "MCPCFG-INV2 violation: max_active_sessions ({}) must be in [{}, {}]",
                self.max_active_sessions, MIN_ACTIVE_SESSIONS, MAX_ALLOWED_ACTIVE_SESSIONS
            ));
        }

        if self.session_idle_timeout_seconds < MIN_IDLE_TIMEOUT || self.session_idle_timeout_seconds > MAX_ALLOWED_IDLE_TIMEOUT {
            return Err(format!(
                "MCPCFG-INV3 violation: session_idle_timeout_seconds ({}) must be in [{}, {}]",
                self.session_idle_timeout_seconds, MIN_IDLE_TIMEOUT, MAX_ALLOWED_IDLE_TIMEOUT
            ));
        }

        if self.default_execution_timeout_seconds < MIN_EXECUTION_TIMEOUT || self.default_execution_timeout_seconds > MAX_ALLOWED_EXECUTION_TIMEOUT {
            return Err(format!(
                "MCPCFG-INV4 violation: default_execution_timeout_seconds ({}) must be in [{}, {}]",
                self.default_execution_timeout_seconds, MIN_EXECUTION_TIMEOUT, MAX_ALLOWED_EXECUTION_TIMEOUT
            ));
        }

        if self.max_arguments_size_bytes < MIN_ARGUMENTS_SIZE || self.max_arguments_size_bytes > MAX_ALLOWED_ARGUMENTS_SIZE {
            return Err(format!(
                "MCPCFG-INV5 violation: max_arguments_size_bytes ({}) must be in [{}, {}]",
                self.max_arguments_size_bytes, MIN_ARGUMENTS_SIZE, MAX_ALLOWED_ARGUMENTS_SIZE
            ));
        }

        if self.max_tools_count < MIN_TOOLS_COUNT || self.max_tools_count > MAX_ALLOWED_TOOLS_COUNT {
            return Err(format!(
                "MCPCFG-INV6 violation: max_tools_count ({}) must be in [{}, {}]",
                self.max_tools_count, MIN_TOOLS_COUNT, MAX_ALLOWED_TOOLS_COUNT
            ));
        }

        Ok(())
    }

    pub fn from_json_str(s: &str) -> Result<Self, String> {
        if s.len() as u64 > MAX_CONFIG_FILE_BYTES {
            return Err(format!("config content exceeds {} bytes", MAX_CONFIG_FILE_BYTES));
        }
        let cfg: Self = serde_json::from_str(s).map_err(|e| format!("parse error: {}", e))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn to_json_str(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("serialization error: {}", e))
    }

    pub fn load_from_file(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let p = path.as_ref();
        let metadata = std::fs::metadata(p).map_err(|e| format!("failed to read file metadata: {}", e))?;
        if metadata.len() > MAX_CONFIG_FILE_BYTES {
            return Err(format!("config file exceeds {} bytes", MAX_CONFIG_FILE_BYTES));
        }
        let content = std::fs::read_to_string(p).map_err(|e| format!("failed to read config file: {}", e))?;
        Self::from_json_str(&content)
    }

    pub fn save_to_file(&self, path: impl AsRef<std::path::Path>) -> Result<(), String> {
        self.validate()?;
        let p = path.as_ref();
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("failed to create dir: {}", e))?;
        }
        let s = self.to_json_str()?;
        std::fs::write(p, s).map_err(|e| format!("failed to write config: {}", e))?;
        Ok(())
    }
}

