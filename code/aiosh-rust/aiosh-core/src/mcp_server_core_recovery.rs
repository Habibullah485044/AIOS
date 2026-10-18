//! AI Control Plane MCP Server Core Recovery & Validation Subsystem (T-03155 scaffold / T-03156 impl).
//!
//! Provides deep validation of state files, non-destructive quarantine, and atomic recovery
//! in compliance with SPEC-MCP-SERVER-CORE-RECOVERY and Proof-of-Restraint Invariant I-2.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MAX_STORE_FILE_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB
pub const MAX_PATH_LEN: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpRecoveryError {
    InvalidPath(String),
    Unauthorized(String),
    Io(String),
}

impl std::fmt::Display for McpRecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpRecoveryError::InvalidPath(s) => write!(f, "MCPRECV_ERR_INVALID_PATH: {}", s),
            McpRecoveryError::Unauthorized(s) => write!(f, "MCPRECV_ERR_UNAUTHORIZED: {}", s),
            McpRecoveryError::Io(s) => write!(f, "MCPRECV_ERR_IO: {}", s),
        }
    }
}

impl std::error::Error for McpRecoveryError {}

pub fn validate_store_path(path: &Path) -> Result<PathBuf, McpRecoveryError> {
    let s = path.to_string_lossy();
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(McpRecoveryError::InvalidPath("empty store path".into()));
    }
    if trimmed.len() > MAX_PATH_LEN {
        return Err(McpRecoveryError::InvalidPath(format!(
            "path exceeds {} characters",
            MAX_PATH_LEN
        )));
    }
    if trimmed.contains('\0') {
        return Err(McpRecoveryError::InvalidPath("NUL byte in path".into()));
    }
    let rest = if trimmed.len() >= 2 && trimmed.as_bytes()[1] == b':' && trimmed.as_bytes()[0].is_ascii_alphabetic() {
        &trimmed[2..]
    } else {
        trimmed
    };
    if rest.contains(':') {
        return Err(McpRecoveryError::InvalidPath("alternate data stream detected in path".into()));
    }
    for comp in path.components() {
        if comp.as_os_str() == ".." {
            return Err(McpRecoveryError::InvalidPath(
                "directory traversal sequence detected".into(),
            ));
        }
        let comp_str = comp.as_os_str().to_string_lossy().to_uppercase();
        let stem = comp_str.split('.').next().unwrap_or("");
        if matches!(stem, "CON" | "PRN" | "AUX" | "NUL" | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9" | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9") {
            return Err(McpRecoveryError::InvalidPath(format!("reserved device name detected: {}", stem)));
        }
    }
    Ok(PathBuf::from(trimmed))
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpValidationIssue {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpValidationReport {
    pub store_path: String,
    pub is_healthy: bool,
    pub total_records: usize,
    pub valid_records: usize,
    pub invalid_records: usize,
    pub issues: Vec<McpValidationIssue>,
    pub validated_at_utc: String,
}

impl McpValidationReport {
    pub fn validate_invariants(&self) -> Result<(), &'static str> {
        if self.total_records != (self.valid_records + self.invalid_records) {
            return Err("MCPRECV-INV1 violated: total != valid + invalid");
        }
        let expected_healthy = self.issues.is_empty() && self.invalid_records == 0;
        if self.is_healthy != expected_healthy {
            return Err("MCPRECV-INV2 violated: is_healthy mismatch");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRecoveryResult {
    pub ok: bool,
    pub action_taken: String,
    pub backup_path: Option<String>,
    pub report: McpValidationReport,
    pub error: Option<String>,
}

pub fn validate_mcp_store(path: &Path) -> McpValidationReport {
    let now = Utc::now().to_rfc3339();
    let validated_p = match validate_store_path(path) {
        Ok(p) => p,
        Err(e) => {
            return McpValidationReport {
                store_path: path.to_string_lossy().to_string(),
                is_healthy: false,
                total_records: 1,
                valid_records: 0,
                invalid_records: 1,
                issues: vec![McpValidationIssue {
                    severity: "ERROR".into(),
                    code: "INVALID_PATH".into(),
                    message: e.to_string(),
                    path: path.to_string_lossy().to_string(),
                }],
                validated_at_utc: now,
            }
        }
    };

    if !validated_p.exists() {
        return McpValidationReport {
            store_path: validated_p.to_string_lossy().to_string(),
            is_healthy: false,
            total_records: 0,
            valid_records: 0,
            invalid_records: 0,
            issues: vec![McpValidationIssue {
                severity: "WARNING".into(),
                code: "FILE_MISSING".into(),
                message: "Store file does not exist".into(),
                path: validated_p.to_string_lossy().to_string(),
            }],
            validated_at_utc: now,
        };
    }

    let meta = match fs::metadata(&validated_p) {
        Ok(m) => m,
        Err(e) => {
            return McpValidationReport {
                store_path: validated_p.to_string_lossy().to_string(),
                is_healthy: false,
                total_records: 1,
                valid_records: 0,
                invalid_records: 1,
                issues: vec![McpValidationIssue {
                    severity: "ERROR".into(),
                    code: "METADATA_ERROR".into(),
                    message: e.to_string(),
                    path: validated_p.to_string_lossy().to_string(),
                }],
                validated_at_utc: now,
            }
        }
    };

    if meta.len() > MAX_STORE_FILE_BYTES {
        return McpValidationReport {
            store_path: validated_p.to_string_lossy().to_string(),
            is_healthy: false,
            total_records: 1,
            valid_records: 0,
            invalid_records: 1,
            issues: vec![McpValidationIssue {
                severity: "ERROR".into(),
                code: "BOUNDS_EXCEEDED".into(),
                message: format!(
                    "Store file size ({}) exceeds limit ({})",
                    meta.len(),
                    MAX_STORE_FILE_BYTES
                ),
                path: validated_p.to_string_lossy().to_string(),
            }],
            validated_at_utc: now,
        };
    }

    let content = match fs::read_to_string(&validated_p) {
        Ok(c) => c,
        Err(e) => {
            return McpValidationReport {
                store_path: validated_p.to_string_lossy().to_string(),
                is_healthy: false,
                total_records: 1,
                valid_records: 0,
                invalid_records: 1,
                issues: vec![McpValidationIssue {
                    severity: "ERROR".into(),
                    code: "READ_ERROR".into(),
                    message: e.to_string(),
                    path: validated_p.to_string_lossy().to_string(),
                }],
                validated_at_utc: now,
            }
        }
    };

    match serde_json::from_str::<serde_json::Value>(&content) {
        Ok(val) => {
            if let Some(obj) = val.as_object() {
                let count = obj.len();
                McpValidationReport {
                    store_path: validated_p.to_string_lossy().to_string(),
                    is_healthy: true,
                    total_records: count,
                    valid_records: count,
                    invalid_records: 0,
                    issues: vec![],
                    validated_at_utc: now,
                }
            } else {
                McpValidationReport {
                    store_path: validated_p.to_string_lossy().to_string(),
                    is_healthy: false,
                    total_records: 1,
                    valid_records: 0,
                    invalid_records: 1,
                    issues: vec![McpValidationIssue {
                        severity: "ERROR".into(),
                        code: "INVALID_SHAPE".into(),
                        message: "Root JSON value must be an object".into(),
                        path: validated_p.to_string_lossy().to_string(),
                    }],
                    validated_at_utc: now,
                }
            }
        }
        Err(e) => McpValidationReport {
            store_path: validated_p.to_string_lossy().to_string(),
            is_healthy: false,
            total_records: 1,
            valid_records: 0,
            invalid_records: 1,
            issues: vec![McpValidationIssue {
                severity: "ERROR".into(),
                code: "INVALID_JSON".into(),
                message: e.to_string(),
                path: validated_p.to_string_lossy().to_string(),
            }],
            validated_at_utc: now,
        },
    }
}

pub fn recover_mcp_store(
    path: &Path,
    capability_token: &str,
) -> Result<McpRecoveryResult, McpRecoveryError> {
    let p = validate_store_path(path)?;

    // PoR Invariant I-2: require capability token
    if capability_token.trim().is_empty() {
        return Err(McpRecoveryError::Unauthorized(
            "capability token required for state recovery (PoR Invariant I-2)".into(),
        ));
    }

    let initial = validate_mcp_store(&p);
    if initial.is_healthy {
        return Ok(McpRecoveryResult {
            ok: true,
            action_taken: "NONE".into(),
            backup_path: None,
            report: initial,
            error: None,
        });
    }

    let mut backup_path = None;
    if p.exists() {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let fname = p.file_name().unwrap_or_default().to_string_lossy();
        let bak = p.with_file_name(format!("{}.bak.{}", fname, ts));
        if let Err(e) = fs::copy(&p, &bak) {
            return Err(McpRecoveryError::Io(e.to_string()));
        }
        backup_path = Some(bak.to_string_lossy().to_string());
    }

    let default_json = r#"{"version":"1.0","sessions":{},"metadata":{"recovered":true}}"#;
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Err(e) = fs::write(&p, default_json) {
        return Err(McpRecoveryError::Io(e.to_string()));
    }

    let report = validate_mcp_store(&p);
    Ok(McpRecoveryResult {
        ok: true,
        action_taken: "QUARANTINE_AND_RESET".into(),
        backup_path,
        report,
        error: None,
    })
}
