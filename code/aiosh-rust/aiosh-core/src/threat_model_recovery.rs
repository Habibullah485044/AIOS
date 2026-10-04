//! Threat Model Maintenance Recovery & Integrity Validation (THREATREC1..THREATREC5).
//!
//! Provides integrity checking, corrupt catalog quarantine, snapshot backup,
//! and crash-consistent repair for the AIOS threat catalog.

use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::canonical::utcnow_iso;
use crate::threat_model_data_model::*;
use crate::threat_model_service::{
    MAX_THREAT_MODEL_STORE_SIZE, ThreatModelService,
};

pub const THREATREC_ERR_IO: &str = "THREATREC_ERR_IO";
pub const THREATREC_ERR_PARSE: &str = "THREATREC_ERR_PARSE";
pub const THREATREC_ERR_PATH_TRAVERSAL: &str = "THREATREC_ERR_PATH_TRAVERSAL";
pub const THREATREC_ERR_FILE_SIZE: &str = "THREATREC_ERR_FILE_SIZE";
pub const THREATREC_ERR_VALIDATION: &str = "THREATREC_ERR_VALIDATION";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCatalogStatus {
    Healthy,
    Degraded,
    Corrupted,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatIssueSeverity {
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatIssueType {
    MissingCatalogFile,
    InvalidJsonSyntax,
    SchemaMismatch,
    CorruptedEntry,
    DuplicateThreatId,
    OversizedPayload,
    SymlinkForbidden,
    InvalidPathTraversal,
    InvalidTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatIntegrityIssue {
    pub severity: ThreatIssueSeverity,
    pub issue_type: ThreatIssueType,
    pub threat_id: Option<String>,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatIntegrityReport {
    pub store_path: String,
    pub status: ThreatCatalogStatus,
    pub total_threats: usize,
    pub valid_threats: usize,
    pub corrupted_threats: usize,
    pub issues: Vec<ThreatIntegrityIssue>,
    pub has_backup: bool,
    pub backup_path: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatRecoveryAction {
    pub action_type: String,
    pub target_id: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatRecoveryReport {
    pub store_path: String,
    pub success: bool,
    pub actions: Vec<ThreatRecoveryAction>,
    pub threats_recovered: usize,
    pub threats_dropped: usize,
    pub quarantined_path: Option<String>,
    pub timestamp: String,
}

pub struct ThreatRecoveryService;

impl ThreatRecoveryService {
    /// Validates path against directory climbing, control chars, UNC, and symlinks.
    pub fn validate_path(path: &Path) -> Result<PathBuf, String> {
        let p_str = path.to_string_lossy();
        if p_str.trim().is_empty() {
            return Err(format!("{}: Path cannot be empty", THREATREC_ERR_PATH_TRAVERSAL));
        }
        if p_str.contains("..")
            || p_str.starts_with("\\\\")
            || p_str.starts_with("//")
            || p_str.chars().any(|c| c.is_control())
        {
            return Err(format!("{}: Path contains forbidden traversal or control characters: {}", THREATREC_ERR_PATH_TRAVERSAL, p_str));
        }
        if path.components().count() > 16 {
            return Err(format!("{}: Path depth exceeds maximum allowed of 16", THREATREC_ERR_PATH_TRAVERSAL));
        }
        if path.exists() {
            if let Ok(meta) = fs::symlink_metadata(path) {
                if meta.file_type().is_symlink() {
                    return Err(format!("{}: Symlinks are forbidden: {}", THREATREC_ERR_PATH_TRAVERSAL, p_str));
                }
            }
        }
        Ok(path.to_path_buf())
    }

    /// Derives the standard backup path `<path>.bak`.
    pub fn backup_path_for(path: &Path) -> PathBuf {
        let mut p = path.to_path_buf().into_os_string();
        p.push(".bak");
        PathBuf::from(p)
    }

    /// Derives quarantine path `<path>.corrupt.<nanos>`.
    pub fn quarantine_path_for(path: &Path) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let mut p = path.to_path_buf().into_os_string();
        p.push(format!(".corrupt.{}.{}", pid, nanos));
        PathBuf::from(p)
    }

    /// Creates a `.bak` snapshot backup of the current catalog file.
    pub fn create_backup(path: &Path) -> Result<PathBuf, String> {
        let valid_path = Self::validate_path(path)?;
        if !valid_path.exists() {
            return Err(format!("{}: Target file does not exist: {}", THREATREC_ERR_IO, valid_path.display()));
        }
        let backup_path = Self::backup_path_for(&valid_path);
        let parent = backup_path.parent().unwrap_or_else(|| Path::new("."));
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| format!("{}: Failed creating parent directory: {}", THREATREC_ERR_IO, e))?;
        }

        let content = fs::read(&valid_path).map_err(|e| format!("{}: Failed reading source: {}", THREATREC_ERR_IO, e))?;
        fs::write(&backup_path, content).map_err(|e| format!("{}: Failed writing backup: {}", THREATREC_ERR_IO, e))?;
        Ok(backup_path)
    }

    /// Non-destructively inspects catalog integrity and reports issues.
    pub fn verify_integrity(path: &Path) -> ThreatIntegrityReport {
        let p_buf = match Self::validate_path(path) {
            Ok(p) => p,
            Err(e) => {
                return ThreatIntegrityReport {
                    store_path: path.to_string_lossy().to_string(),
                    status: ThreatCatalogStatus::Corrupted,
                    total_threats: 0,
                    valid_threats: 0,
                    corrupted_threats: 0,
                    issues: vec![ThreatIntegrityIssue {
                        severity: ThreatIssueSeverity::Critical,
                        issue_type: ThreatIssueType::InvalidPathTraversal,
                        threat_id: None,
                        details: e,
                    }],
                    has_backup: false,
                    backup_path: None,
                    timestamp: utcnow_iso(),
                };
            }
        };

        let backup_p = Self::backup_path_for(&p_buf);
        let has_backup = backup_p.exists();
        let backup_str = if has_backup { Some(backup_p.to_string_lossy().to_string()) } else { None };

        if !p_buf.exists() {
            return ThreatIntegrityReport {
                store_path: p_buf.to_string_lossy().to_string(),
                status: ThreatCatalogStatus::Missing,
                total_threats: 0,
                valid_threats: 0,
                corrupted_threats: 0,
                issues: vec![ThreatIntegrityIssue {
                    severity: ThreatIssueSeverity::Warning,
                    issue_type: ThreatIssueType::MissingCatalogFile,
                    threat_id: None,
                    details: "Threat model store file does not exist".to_string(),
                }],
                has_backup,
                backup_path: backup_str,
                timestamp: utcnow_iso(),
            };
        }

        let meta = match fs::metadata(&p_buf) {
            Ok(m) => m,
            Err(e) => {
                return ThreatIntegrityReport {
                    store_path: p_buf.to_string_lossy().to_string(),
                    status: ThreatCatalogStatus::Corrupted,
                    total_threats: 0,
                    valid_threats: 0,
                    corrupted_threats: 0,
                    issues: vec![ThreatIntegrityIssue {
                        severity: ThreatIssueSeverity::Critical,
                        issue_type: ThreatIssueType::InvalidJsonSyntax,
                        threat_id: None,
                        details: format!("Metadata error: {}", e),
                    }],
                    has_backup,
                    backup_path: backup_str,
                    timestamp: utcnow_iso(),
                };
            }
        };

        if meta.len() > MAX_THREAT_MODEL_STORE_SIZE {
            return ThreatIntegrityReport {
                store_path: p_buf.to_string_lossy().to_string(),
                status: ThreatCatalogStatus::Corrupted,
                total_threats: 0,
                valid_threats: 0,
                corrupted_threats: 0,
                issues: vec![ThreatIntegrityIssue {
                    severity: ThreatIssueSeverity::Critical,
                    issue_type: ThreatIssueType::OversizedPayload,
                    threat_id: None,
                    details: format!("File size {} exceeds maximum allowed {}", meta.len(), MAX_THREAT_MODEL_STORE_SIZE),
                }],
                has_backup,
                backup_path: backup_str,
                timestamp: utcnow_iso(),
            };
        }

        let content = match fs::read_to_string(&p_buf) {
            Ok(c) => c,
            Err(e) => {
                return ThreatIntegrityReport {
                    store_path: p_buf.to_string_lossy().to_string(),
                    status: ThreatCatalogStatus::Corrupted,
                    total_threats: 0,
                    valid_threats: 0,
                    corrupted_threats: 0,
                    issues: vec![ThreatIntegrityIssue {
                        severity: ThreatIssueSeverity::Critical,
                        issue_type: ThreatIssueType::InvalidJsonSyntax,
                        threat_id: None,
                        details: format!("Read error: {}", e),
                    }],
                    has_backup,
                    backup_path: backup_str,
                    timestamp: utcnow_iso(),
                };
            }
        };

        let snapshot: ThreatModelSnapshot = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => {
                return ThreatIntegrityReport {
                    store_path: p_buf.to_string_lossy().to_string(),
                    status: ThreatCatalogStatus::Corrupted,
                    total_threats: 0,
                    valid_threats: 0,
                    corrupted_threats: 0,
                    issues: vec![ThreatIntegrityIssue {
                        severity: ThreatIssueSeverity::Critical,
                        issue_type: ThreatIssueType::InvalidJsonSyntax,
                        threat_id: None,
                        details: format!("JSON parse error: {}", e),
                    }],
                    has_backup,
                    backup_path: backup_str,
                    timestamp: utcnow_iso(),
                };
            }
        };

        let mut issues = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();
        let mut valid_count = 0;
        let mut corrupted_count = 0;

        for entry in &snapshot.threats {
            let mut entry_corrupt = false;
            if let Err(e) = ThreatEntry::validate_id(&entry.id) {
                issues.push(ThreatIntegrityIssue {
                    severity: ThreatIssueSeverity::Error,
                    issue_type: ThreatIssueType::CorruptedEntry,
                    threat_id: Some(entry.id.clone()),
                    details: format!("Invalid ID: {}", e),
                });
                entry_corrupt = true;
            } else if !seen_ids.insert(entry.id.clone()) {
                issues.push(ThreatIntegrityIssue {
                    severity: ThreatIssueSeverity::Error,
                    issue_type: ThreatIssueType::DuplicateThreatId,
                    threat_id: Some(entry.id.clone()),
                    details: format!("Duplicate threat ID: {}", entry.id),
                });
                entry_corrupt = true;
            }

            if let Err(e) = ThreatEntry::validate_title(&entry.title) {
                issues.push(ThreatIntegrityIssue {
                    severity: ThreatIssueSeverity::Error,
                    issue_type: ThreatIssueType::CorruptedEntry,
                    threat_id: Some(entry.id.clone()),
                    details: format!("Invalid title: {}", e),
                });
                entry_corrupt = true;
            }

            if let Err(e) = ThreatEntry::validate_description(&entry.description) {
                issues.push(ThreatIntegrityIssue {
                    severity: ThreatIssueSeverity::Error,
                    issue_type: ThreatIssueType::CorruptedEntry,
                    threat_id: Some(entry.id.clone()),
                    details: format!("Invalid description: {}", e),
                });
                entry_corrupt = true;
            }

            if entry_corrupt {
                corrupted_count += 1;
            } else {
                valid_count += 1;
            }
        }

        let total = snapshot.threats.len();
        let status = if issues.is_empty() {
            ThreatCatalogStatus::Healthy
        } else if valid_count > 0 {
            ThreatCatalogStatus::Degraded
        } else {
            ThreatCatalogStatus::Corrupted
        };

        ThreatIntegrityReport {
            store_path: p_buf.to_string_lossy().to_string(),
            status,
            total_threats: total,
            valid_threats: valid_count,
            corrupted_threats: corrupted_count,
            issues,
            has_backup,
            backup_path: backup_str,
            timestamp: utcnow_iso(),
        }
    }

    /// Repairs corrupted catalog, salvages valid entries, and preserves quarantine backup.
    pub fn repair_catalog(path: &Path) -> Result<ThreatRecoveryReport, String> {
        let valid_path = Self::validate_path(path)?;
        if !valid_path.exists() {
            // If missing, seed with canonical STRIDE baseline
            let svc = ThreatModelService::with_canonical_threats();
            svc.save_to_path(&valid_path)?;
            return Ok(ThreatRecoveryReport {
                store_path: valid_path.to_string_lossy().to_string(),
                success: true,
                actions: vec![ThreatRecoveryAction {
                    action_type: "seed_canonical".to_string(),
                    target_id: None,
                    description: "Missing file recreated with canonical STRIDE catalog".to_string(),
                }],
                threats_recovered: svc.snapshot.threats.len(),
                threats_dropped: 0,
                quarantined_path: None,
                timestamp: utcnow_iso(),
            });
        }

        // Try reading content
        let content = fs::read_to_string(&valid_path).map_err(|e| format!("{}: Read error: {}", THREATREC_ERR_IO, e))?;
        let quarantine_path = Self::quarantine_path_for(&valid_path);

        // Move to quarantine
        fs::copy(&valid_path, &quarantine_path).map_err(|e| format!("{}: Failed copying to quarantine: {}", THREATREC_ERR_IO, e))?;

        let mut actions = Vec::new();
        actions.push(ThreatRecoveryAction {
            action_type: "quarantine".to_string(),
            target_id: None,
            description: format!("Original store quarantined to {}", quarantine_path.display()),
        });

        // Parse or salvage
        let mut salvaged_entries = Vec::new();
        let mut dropped_count = 0;

        match serde_json::from_str::<ThreatModelSnapshot>(&content) {
            Ok(snapshot) => {
                let mut seen_ids = std::collections::HashSet::new();
                for entry in snapshot.threats {
                    let is_valid = ThreatEntry::validate_id(&entry.id).is_ok()
                        && ThreatEntry::validate_title(&entry.title).is_ok()
                        && ThreatEntry::validate_description(&entry.description).is_ok()
                        && seen_ids.insert(entry.id.clone());

                    if is_valid {
                        salvaged_entries.push(entry);
                    } else {
                        dropped_count += 1;
                        actions.push(ThreatRecoveryAction {
                            action_type: "drop_corrupted_entry".to_string(),
                            target_id: Some(entry.id.clone()),
                            description: format!("Dropped corrupted threat entry {}", entry.id),
                        });
                    }
                }
            }
            Err(_) => {
                // If completely invalid JSON, attempt raw regex or fallback to canonical STRIDE
                let fallback = ThreatModelService::with_canonical_threats();
                salvaged_entries = fallback.snapshot.threats;
                actions.push(ThreatRecoveryAction {
                    action_type: "fallback_canonical".to_string(),
                    target_id: None,
                    description: "Unparseable JSON repaired using canonical STRIDE baseline".to_string(),
                });
            }
        }

        let mut repaired_snapshot = ThreatModelSnapshot::new("1.0.0");
        repaired_snapshot.threats = salvaged_entries;
        repaired_snapshot.generated_at = utcnow_iso();

        let repaired_svc = ThreatModelService {
            snapshot: repaired_snapshot,
            policy: None,
        };
        repaired_svc.save_to_path(&valid_path)?;

        let recovered = repaired_svc.snapshot.threats.len();
        actions.push(ThreatRecoveryAction {
            action_type: "atomic_write".to_string(),
            target_id: None,
            description: format!("Clean catalog persisted with {} entries", recovered),
        });

        Ok(ThreatRecoveryReport {
            store_path: valid_path.to_string_lossy().to_string(),
            success: true,
            actions,
            threats_recovered: recovered,
            threats_dropped: dropped_count,
            quarantined_path: Some(quarantine_path.to_string_lossy().to_string()),
            timestamp: utcnow_iso(),
        })
    }

    /// Restores catalog from `.bak` backup file.
    pub fn restore_from_backup(path: &Path) -> Result<ThreatRecoveryReport, String> {
        let valid_path = Self::validate_path(path)?;
        let backup_path = Self::backup_path_for(&valid_path);

        if !backup_path.exists() {
            return Err(format!("{}: Backup file not found: {}", THREATREC_ERR_IO, backup_path.display()));
        }

        // Verify backup integrity first
        let backup_report = Self::verify_integrity(&backup_path);
        if backup_report.status == ThreatCatalogStatus::Corrupted {
            return Err(format!("{}: Backup file is itself corrupted: {:?}", THREATREC_ERR_VALIDATION, backup_report.issues));
        }

        // Quarantine current file if it exists
        let mut quarantined = None;
        if valid_path.exists() {
            let q_path = Self::quarantine_path_for(&valid_path);
            let _ = fs::copy(&valid_path, &q_path);
            quarantined = Some(q_path.to_string_lossy().to_string());
        }

        // Copy backup to target
        let backup_content = fs::read_to_string(&backup_path)
            .map_err(|e| format!("{}: Failed reading backup: {}", THREATREC_ERR_IO, e))?;
        let snapshot: ThreatModelSnapshot = serde_json::from_str(&backup_content)
            .map_err(|e| format!("{}: Failed parsing backup JSON: {}", THREATREC_ERR_PARSE, e))?;

        let svc = ThreatModelService {
            snapshot,
            policy: None,
        };
        svc.save_to_path(&valid_path)?;

        Ok(ThreatRecoveryReport {
            store_path: valid_path.to_string_lossy().to_string(),
            success: true,
            actions: vec![
                ThreatRecoveryAction {
                    action_type: "restore_from_backup".to_string(),
                    target_id: None,
                    description: format!("Catalog restored from {}", backup_path.display()),
                },
            ],
            threats_recovered: svc.snapshot.threats.len(),
            threats_dropped: 0,
            quarantined_path: quarantined,
            timestamp: utcnow_iso(),
        })
    }
}
