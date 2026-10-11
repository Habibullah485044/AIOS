//! Compliance Mapping Recovery & Integrity Validation (COMPLYREC1..COMPLYREC5).
//!
//! Provides integrity checking, corrupt catalog quarantine, snapshot backup,
//! and crash-consistent repair for the AIOS compliance catalog.

use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::canonical::utcnow_iso;
use crate::compliance_data_model::*;
use crate::compliance_service::{ComplianceService, MAX_COMPLIANCE_STORE_SIZE};

pub const COMPLYREC_ERR_IO: &str = "COMPLYREC_ERR_IO";
pub const COMPLYREC_ERR_PARSE: &str = "COMPLYREC_ERR_PARSE";
pub const COMPLYREC_ERR_PATH_TRAVERSAL: &str = "COMPLYREC_ERR_PATH_TRAVERSAL";
pub const COMPLYREC_ERR_FILE_SIZE: &str = "COMPLYREC_ERR_FILE_SIZE";
pub const COMPLYREC_ERR_VALIDATION: &str = "COMPLYREC_ERR_VALIDATION";
pub const COMPLYREC_ERR_NO_BACKUP: &str = "COMPLYREC_ERR_NO_BACKUP";
pub const MAX_QUARANTINE_FILES: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceCatalogStatus {
    Healthy,
    Degraded,
    Corrupted,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceIssueSeverity {
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceIssueType {
    MissingCatalogFile,
    InvalidJsonSyntax,
    SchemaMismatch,
    CorruptedEntry,
    DuplicateMappingId,
    OversizedPayload,
    SymlinkForbidden,
    InvalidPathTraversal,
    InvalidTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceIntegrityIssue {
    pub severity: ComplianceIssueSeverity,
    pub issue_type: ComplianceIssueType,
    pub mapping_id: Option<String>,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceIntegrityReport {
    pub store_path: String,
    pub status: ComplianceCatalogStatus,
    pub total_mappings: usize,
    pub valid_mappings: usize,
    pub corrupted_mappings: usize,
    pub issues: Vec<ComplianceIntegrityIssue>,
    pub has_backup: bool,
    pub backup_path: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceRecoveryAction {
    pub action_type: String,
    pub target_id: Option<String>,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceRecoveryReport {
    pub store_path: String,
    pub success: bool,
    pub actions: Vec<ComplianceRecoveryAction>,
    pub mappings_recovered: usize,
    pub mappings_dropped: usize,
    pub quarantined_path: Option<String>,
    pub timestamp: String,
}

pub struct ComplianceRecoveryService;

impl ComplianceRecoveryService {
    /// Validates path against directory climbing, control chars, UNC, and symlinks.
    pub fn validate_path(path: &Path) -> Result<PathBuf, String> {
        let p_str = path.to_string_lossy();
        if p_str.trim().is_empty() {
            return Err(format!("{}: Path cannot be empty", COMPLYREC_ERR_PATH_TRAVERSAL));
        }
        if p_str.contains("..")
            || p_str.starts_with("\\\\")
            || p_str.starts_with("//")
            || p_str.chars().any(|c| c.is_control())
        {
            return Err(format!(
                "{}: Path contains forbidden traversal or control characters: {}",
                COMPLYREC_ERR_PATH_TRAVERSAL, p_str
            ));
        }
        if path.components().count() > 16 {
            return Err(format!(
                "{}: Path depth exceeds maximum allowed of 16",
                COMPLYREC_ERR_PATH_TRAVERSAL
            ));
        }
        if path.exists() {
            if let Ok(meta) = fs::symlink_metadata(path) {
                if meta.file_type().is_symlink() {
                    return Err(format!(
                        "{}: Symlinks are forbidden: {}",
                        COMPLYREC_ERR_PATH_TRAVERSAL, p_str
                    ));
                }
            }
        }
        Ok(path.to_path_buf())
    }

    /// Derives standard backup path `<path>.bak`.
    pub fn backup_path_for(path: &Path) -> PathBuf {
        let mut p = path.to_path_buf().into_os_string();
        p.push(".bak");
        PathBuf::from(p)
    }

    /// Derives quarantine path `<path>.corrupt.<pid>.<nanos>` and prunes oldest if exceeding MAX_QUARANTINE_FILES.
    pub fn quarantine_path_for(path: &Path) -> PathBuf {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("compliance_map.json");
        Self::prune_old_quarantine_files(parent, fname);

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let mut p = path.to_path_buf().into_os_string();
        p.push(format!(".corrupt.{}.{}", pid, nanos));
        PathBuf::from(p)
    }

    /// Prunes older quarantine files exceeding MAX_QUARANTINE_FILES to prevent disk exhaustion (CWE-400).
    pub fn prune_old_quarantine_files(parent: &Path, base_fname: &str) -> usize {
        let pattern_prefix = format!("{}.corrupt.", base_fname);
        let mut entries: Vec<PathBuf> = match fs::read_dir(parent) {
            Ok(read_dir) => read_dir
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|s| s.starts_with(&pattern_prefix))
                        .unwrap_or(false)
                })
                .collect(),
            Err(_) => return 0,
        };

        if entries.len() <= MAX_QUARANTINE_FILES {
            return 0;
        }

        // Sort by metadata modified time (oldest first)
        entries.sort_by_key(|p| fs::metadata(p).and_then(|m| m.modified()).ok());

        let to_remove = entries.len().saturating_sub(MAX_QUARANTINE_FILES);
        let mut removed = 0;
        for path in entries.iter().take(to_remove) {
            if fs::remove_file(path).is_ok() {
                removed += 1;
            }
        }
        removed
    }

    /// Creates a `.bak` snapshot backup of the current compliance catalog with atomic write.
    pub fn create_backup(path: &Path) -> Result<PathBuf, String> {
        let valid_path = Self::validate_path(path)?;
        if !valid_path.exists() {
            return Err(format!(
                "{}: Target file does not exist: {}",
                COMPLYREC_ERR_IO,
                valid_path.display()
            ));
        }
        let backup_path = Self::backup_path_for(&valid_path);
        let parent = backup_path.parent().unwrap_or_else(|| Path::new("."));
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("{}: Failed creating parent directory: {}", COMPLYREC_ERR_IO, e))?;
        }

        let content = fs::read(&valid_path)
            .map_err(|e| format!("{}: Failed reading source: {}", COMPLYREC_ERR_IO, e))?;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let fname = backup_path.file_name().and_then(|n| n.to_str()).unwrap_or("backup");
        let tmp_path = parent.join(format!(".{}.tmp.{}.{}", fname, pid, nanos));

        if let Err(e) = fs::write(&tmp_path, content) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("{}: Failed writing backup tmp file: {}", COMPLYREC_ERR_IO, e));
        }
        if let Err(e) = fs::rename(&tmp_path, &backup_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("{}: Failed atomic rename to backup: {}", COMPLYREC_ERR_IO, e));
        }
        Ok(backup_path)
    }

    /// Non-destructively inspects catalog integrity and reports issues.
    pub fn verify_integrity(path: &Path) -> ComplianceIntegrityReport {
        let p_buf = match Self::validate_path(path) {
            Ok(p) => p,
            Err(e) => {
                return ComplianceIntegrityReport {
                    store_path: path.to_string_lossy().to_string(),
                    status: ComplianceCatalogStatus::Corrupted,
                    total_mappings: 0,
                    valid_mappings: 0,
                    corrupted_mappings: 0,
                    issues: vec![ComplianceIntegrityIssue {
                        severity: ComplianceIssueSeverity::Critical,
                        issue_type: ComplianceIssueType::InvalidPathTraversal,
                        mapping_id: None,
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
        let backup_str = if has_backup {
            Some(backup_p.to_string_lossy().to_string())
        } else {
            None
        };

        if !p_buf.exists() {
            return ComplianceIntegrityReport {
                store_path: p_buf.to_string_lossy().to_string(),
                status: ComplianceCatalogStatus::Missing,
                total_mappings: 0,
                valid_mappings: 0,
                corrupted_mappings: 0,
                issues: vec![ComplianceIntegrityIssue {
                    severity: ComplianceIssueSeverity::Warning,
                    issue_type: ComplianceIssueType::MissingCatalogFile,
                    mapping_id: None,
                    details: "Compliance map store file does not exist".to_string(),
                }],
                has_backup,
                backup_path: backup_str,
                timestamp: utcnow_iso(),
            };
        }

        let meta = match fs::metadata(&p_buf) {
            Ok(m) => m,
            Err(e) => {
                return ComplianceIntegrityReport {
                    store_path: p_buf.to_string_lossy().to_string(),
                    status: ComplianceCatalogStatus::Corrupted,
                    total_mappings: 0,
                    valid_mappings: 0,
                    corrupted_mappings: 0,
                    issues: vec![ComplianceIntegrityIssue {
                        severity: ComplianceIssueSeverity::Critical,
                        issue_type: ComplianceIssueType::InvalidJsonSyntax,
                        mapping_id: None,
                        details: format!("Metadata error: {}", e),
                    }],
                    has_backup,
                    backup_path: backup_str,
                    timestamp: utcnow_iso(),
                };
            }
        };

        if meta.len() > MAX_COMPLIANCE_STORE_SIZE {
            return ComplianceIntegrityReport {
                store_path: p_buf.to_string_lossy().to_string(),
                status: ComplianceCatalogStatus::Corrupted,
                total_mappings: 0,
                valid_mappings: 0,
                corrupted_mappings: 0,
                issues: vec![ComplianceIntegrityIssue {
                    severity: ComplianceIssueSeverity::Critical,
                    issue_type: ComplianceIssueType::OversizedPayload,
                    mapping_id: None,
                    details: format!(
                        "File size {} exceeds maximum allowed {}",
                        meta.len(),
                        MAX_COMPLIANCE_STORE_SIZE
                    ),
                }],
                has_backup,
                backup_path: backup_str,
                timestamp: utcnow_iso(),
            };
        }

        let content = match fs::read_to_string(&p_buf) {
            Ok(c) => c,
            Err(e) => {
                return ComplianceIntegrityReport {
                    store_path: p_buf.to_string_lossy().to_string(),
                    status: ComplianceCatalogStatus::Corrupted,
                    total_mappings: 0,
                    valid_mappings: 0,
                    corrupted_mappings: 0,
                    issues: vec![ComplianceIntegrityIssue {
                        severity: ComplianceIssueSeverity::Critical,
                        issue_type: ComplianceIssueType::InvalidJsonSyntax,
                        mapping_id: None,
                        details: format!("Read error: {}", e),
                    }],
                    has_backup,
                    backup_path: backup_str,
                    timestamp: utcnow_iso(),
                };
            }
        };

        let snapshot: ComplianceCatalogSnapshot = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => {
                return ComplianceIntegrityReport {
                    store_path: p_buf.to_string_lossy().to_string(),
                    status: ComplianceCatalogStatus::Corrupted,
                    total_mappings: 0,
                    valid_mappings: 0,
                    corrupted_mappings: 0,
                    issues: vec![ComplianceIntegrityIssue {
                        severity: ComplianceIssueSeverity::Critical,
                        issue_type: ComplianceIssueType::InvalidJsonSyntax,
                        mapping_id: None,
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

        for entry in &snapshot.mappings {
            let mut entry_corrupt = false;
            if let Err(e) = validate_identifier(&entry.id, "Mapping ID") {
                issues.push(ComplianceIntegrityIssue {
                    severity: ComplianceIssueSeverity::Error,
                    issue_type: ComplianceIssueType::CorruptedEntry,
                    mapping_id: Some(entry.id.clone()),
                    details: format!("Invalid ID: {}", e),
                });
                entry_corrupt = true;
            } else if !seen_ids.insert(entry.id.clone()) {
                issues.push(ComplianceIntegrityIssue {
                    severity: ComplianceIssueSeverity::Error,
                    issue_type: ComplianceIssueType::DuplicateMappingId,
                    mapping_id: Some(entry.id.clone()),
                    details: format!("Duplicate mapping ID: {}", entry.id),
                });
                entry_corrupt = true;
            }

            if entry.control_id.trim().is_empty() {
                issues.push(ComplianceIntegrityIssue {
                    severity: ComplianceIssueSeverity::Error,
                    issue_type: ComplianceIssueType::CorruptedEntry,
                    mapping_id: Some(entry.id.clone()),
                    details: "Empty control ID".to_string(),
                });
                entry_corrupt = true;
            }

            if entry.target_ref.trim().is_empty() {
                issues.push(ComplianceIntegrityIssue {
                    severity: ComplianceIssueSeverity::Error,
                    issue_type: ComplianceIssueType::CorruptedEntry,
                    mapping_id: Some(entry.id.clone()),
                    details: "Empty target reference".to_string(),
                });
                entry_corrupt = true;
            }

            if entry_corrupt {
                corrupted_count += 1;
            } else {
                valid_count += 1;
            }
        }

        let total = snapshot.mappings.len();
        let status = if issues.is_empty() {
            ComplianceCatalogStatus::Healthy
        } else if valid_count > 0 {
            ComplianceCatalogStatus::Degraded
        } else {
            ComplianceCatalogStatus::Corrupted
        };

        ComplianceIntegrityReport {
            store_path: p_buf.to_string_lossy().to_string(),
            status,
            total_mappings: total,
            valid_mappings: valid_count,
            corrupted_mappings: corrupted_count,
            issues,
            has_backup,
            backup_path: backup_str,
            timestamp: utcnow_iso(),
        }
    }

    /// Repairs corrupted catalog, salvages valid entries, and preserves quarantine backup.
    pub fn repair_catalog(path: &Path) -> Result<ComplianceRecoveryReport, String> {
        let valid_path = Self::validate_path(path)?;
        if !valid_path.exists() {
            let svc = ComplianceService::with_canonical_baseline();
            svc.save_to_path(&valid_path)?;
            return Ok(ComplianceRecoveryReport {
                store_path: valid_path.to_string_lossy().to_string(),
                success: true,
                actions: vec![ComplianceRecoveryAction {
                    action_type: "seed_canonical".to_string(),
                    target_id: None,
                    description: "Missing file recreated with canonical compliance catalog".to_string(),
                }],
                mappings_recovered: svc.snapshot.mappings.len(),
                mappings_dropped: 0,
                quarantined_path: None,
                timestamp: utcnow_iso(),
            });
        }

        let content = fs::read_to_string(&valid_path)
            .map_err(|e| format!("{}: Read error: {}", COMPLYREC_ERR_IO, e))?;
        let quarantine_path = Self::quarantine_path_for(&valid_path);

        fs::copy(&valid_path, &quarantine_path)
            .map_err(|e| format!("{}: Failed copying to quarantine: {}", COMPLYREC_ERR_IO, e))?;

        let mut actions = Vec::new();
        actions.push(ComplianceRecoveryAction {
            action_type: "quarantine".to_string(),
            target_id: None,
            description: format!("Original store quarantined to {}", quarantine_path.display()),
        });

        let mut salvaged_entries = Vec::new();
        let mut dropped_count = 0;

        match serde_json::from_str::<ComplianceCatalogSnapshot>(&content) {
            Ok(snapshot) => {
                let mut seen_ids = std::collections::HashSet::new();
                for entry in snapshot.mappings {
                    let is_valid = validate_identifier(&entry.id, "Mapping ID").is_ok()
                        && !entry.control_id.trim().is_empty()
                        && !entry.target_ref.trim().is_empty()
                        && seen_ids.insert(entry.id.clone());

                    if is_valid {
                        salvaged_entries.push(entry);
                    } else {
                        dropped_count += 1;
                        actions.push(ComplianceRecoveryAction {
                            action_type: "drop_corrupted_entry".to_string(),
                            target_id: Some(entry.id.clone()),
                            description: format!("Dropped corrupted mapping entry {}", entry.id),
                        });
                    }
                }
            }
            Err(_) => {
                let fallback = ComplianceService::with_canonical_baseline();
                salvaged_entries = fallback.snapshot.mappings;
                actions.push(ComplianceRecoveryAction {
                    action_type: "fallback_canonical".to_string(),
                    target_id: None,
                    description: "Unparseable JSON repaired using canonical compliance baseline".to_string(),
                });
            }
        }

        let mut repaired_snapshot = ComplianceCatalogSnapshot::new("1.0.0");
        repaired_snapshot.mappings = salvaged_entries;
        repaired_snapshot.generated_at = utcnow_iso();

        let repaired_svc = ComplianceService {
            snapshot: repaired_snapshot,
            policy: None,
        };
        repaired_svc.save_to_path(&valid_path)?;

        let recovered = repaired_svc.snapshot.mappings.len();
        actions.push(ComplianceRecoveryAction {
            action_type: "atomic_write".to_string(),
            target_id: None,
            description: format!("Clean catalog persisted with {} entries", recovered),
        });

        Ok(ComplianceRecoveryReport {
            store_path: valid_path.to_string_lossy().to_string(),
            success: true,
            actions,
            mappings_recovered: recovered,
            mappings_dropped: dropped_count,
            quarantined_path: Some(quarantine_path.to_string_lossy().to_string()),
            timestamp: utcnow_iso(),
        })
    }

    /// Restores catalog from `.bak` backup file.
    pub fn restore_from_backup(path: &Path) -> Result<ComplianceRecoveryReport, String> {
        let valid_path = Self::validate_path(path)?;
        let backup_path = Self::backup_path_for(&valid_path);

        if !backup_path.exists() {
            return Err(format!(
                "{}: Backup file not found: {}",
                COMPLYREC_ERR_NO_BACKUP,
                backup_path.display()
            ));
        }

        let backup_report = Self::verify_integrity(&backup_path);
        if backup_report.status == ComplianceCatalogStatus::Corrupted {
            return Err(format!(
                "{}: Backup file is itself corrupted: {:?}",
                COMPLYREC_ERR_VALIDATION, backup_report.issues
            ));
        }

        let mut quarantined = None;
        if valid_path.exists() {
            let q_path = Self::quarantine_path_for(&valid_path);
            let _ = fs::copy(&valid_path, &q_path);
            quarantined = Some(q_path.to_string_lossy().to_string());
        }

        let content = fs::read(&backup_path)
            .map_err(|e| format!("{}: Failed reading backup file: {}", COMPLYREC_ERR_IO, e))?;

        let parent = valid_path.parent().unwrap_or_else(|| Path::new("."));
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let fname = valid_path.file_name().and_then(|n| n.to_str()).unwrap_or("store");
        let tmp_path = parent.join(format!(".{}.tmp.{}.{}", fname, pid, nanos));

        if let Err(e) = fs::write(&tmp_path, content) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("{}: Failed writing restored tmp file: {}", COMPLYREC_ERR_IO, e));
        }
        if let Err(e) = fs::rename(&tmp_path, &valid_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("{}: Failed atomic rename to restored target: {}", COMPLYREC_ERR_IO, e));
        }

        let restored_report = Self::verify_integrity(&valid_path);

        Ok(ComplianceRecoveryReport {
            store_path: valid_path.to_string_lossy().to_string(),
            success: true,
            actions: vec![ComplianceRecoveryAction {
                action_type: "restore_from_backup".to_string(),
                target_id: None,
                description: format!("Restored store from {}", backup_path.display()),
            }],
            mappings_recovered: restored_report.valid_mappings,
            mappings_dropped: 0,
            quarantined_path: quarantined,
            timestamp: utcnow_iso(),
        })
    }
}
