//! Secrets Handling Recovery & Validation Subsystem (SECREC1..SECREC5).
//!
//! Provides integrity checking, snapshot backups, crash-consistent repair,
//! and validation reporting for the runtime secrets vault.

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

pub const SECREC_ERR_PATH_TRAVERSAL: &str = "SECREC_ERR_PATH_TRAVERSAL";
pub const SECREC_ERR_IO: &str = "SECREC_ERR_IO";
pub const SECREC_ERR_CORRUPT: &str = "SECREC_ERR_CORRUPT";
pub const SECREC_ERR_BACKUP_NOT_FOUND: &str = "SECREC_ERR_BACKUP_NOT_FOUND";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretVaultStatus {
    Healthy,
    Degraded,
    Corrupted,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretIssueSeverity {
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretIntegrityIssue {
    pub severity: SecretIssueSeverity,
    pub issue_type: String,
    pub secret_id: Option<String>,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretIntegrityReport {
    pub vault_path: String,
    pub status: SecretVaultStatus,
    pub total_records: usize,
    pub valid_records: usize,
    pub corrupted_records: usize,
    pub issues: Vec<SecretIntegrityIssue>,
    pub has_backup: bool,
    pub backup_path: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRecoveryAction {
    pub action_type: String,
    pub target_id: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRecoveryReport {
    pub vault_path: String,
    pub success: bool,
    pub actions: Vec<SecretRecoveryAction>,
    pub records_recovered: usize,
    pub records_dropped: usize,
    pub quarantined_path: Option<String>,
    pub timestamp: String,
}

pub struct SecretRecoveryService;

impl SecretRecoveryService {
    pub fn validate_path(path: &Path) -> Result<PathBuf, String> {
        let p_str = path.to_string_lossy();
        if p_str.contains("..") || p_str.chars().any(|c| c.is_control()) {
            return Err(format!("{}: Path contains forbidden sequences: {}", SECREC_ERR_PATH_TRAVERSAL, p_str));
        }
        Ok(path.to_path_buf())
    }

    pub fn backup_path_for(path: &Path) -> PathBuf {
        let mut p = path.to_path_buf();
        let ext = p.extension().unwrap_or_default().to_string_lossy().to_string();
        if ext.is_empty() {
            p.set_extension("bak");
        } else {
            p.set_extension(format!("{}.bak", ext));
        }
        p
    }
}
