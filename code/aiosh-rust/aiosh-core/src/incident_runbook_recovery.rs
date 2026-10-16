//! Incident Response Runbooks Recovery & Validation Subsystem (IRREC1..IRREC5).
//!
//! Provides non-destructive integrity checking, corrupted state quarantine,
//! snapshot restoration, and crash-consistent repair for Incident Response Runbooks.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::canonical::utcnow_iso;
use crate::incident_runbook_data_model::RunbookCatalogSnapshot;

pub const IRREC_ERR_IO: &str = "IRREC_ERR_IO";
pub const IRREC_ERR_PARSE: &str = "IRREC_ERR_PARSE";
pub const IRREC_ERR_PATH_TRAVERSAL: &str = "IRREC_ERR_PATH_TRAVERSAL";
pub const IRREC_ERR_FILE_SIZE: &str = "IRREC_ERR_FILE_SIZE";
pub const IRREC_ERR_VALIDATION: &str = "IRREC_ERR_VALIDATION";
pub const IRREC_ERR_NO_BACKUP: &str = "IRREC_ERR_NO_BACKUP";

pub const MAX_RUNBOOK_STATE_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB
pub const MAX_QUARANTINE_FILES: usize = 10;
pub const MAX_BACKUP_FILES: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookCatalogStatus {
    Healthy,
    Degraded,
    Corrupted,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookIssueSeverity {
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookIssueType {
    MissingStateFile,
    InvalidJsonSyntax,
    InvalidTomlSyntax,
    SchemaMismatch,
    CorruptedEntry,
    DuplicateRunbookId,
    OversizedPayload,
    SymlinkForbidden,
    InvalidPathTraversal,
    ExcessiveActiveSessions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookValidationIssue {
    pub issue_type: RunbookIssueType,
    pub severity: RunbookIssueSeverity,
    pub message: String,
    pub target_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookValidationReport {
    pub status: RunbookCatalogStatus,
    pub checked_at_utc: String,
    pub target_path: String,
    pub issues: Vec<RunbookValidationIssue>,
    pub total_runbooks: usize,
    pub total_active_sessions: usize,
    pub is_recoverable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookRecoveryReport {
    pub ok: bool,
    pub recovered_at_utc: String,
    pub quarantine_path: Option<String>,
    pub backup_path: Option<String>,
    pub restored_runbooks_count: usize,
    pub action_taken: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookRecoveryResultEnvelope<T> {
    pub ok: bool,
    pub data: Option<T>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub audit_row_required: bool,
}

impl<T> RunbookRecoveryResultEnvelope<T> {
    pub fn success(data: T) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error_code: None,
            error_message: None,
            audit_row_required: false,
        }
    }

    pub fn failure(code: &str, message: &str) -> Self {
        Self {
            ok: false,
            data: None,
            error_code: Some(code.to_string()),
            error_message: Some(message.to_string()),
            audit_row_required: true,
        }
    }
}

pub struct RunbookRecoveryService;

impl RunbookRecoveryService {
    /// Validates path against directory traversal and null bytes.
    pub fn validate_path(path: &Path) -> Result<PathBuf, String> {
        let s = path.to_string_lossy();
        if s.trim().is_empty() {
            return Err(format!("{}: empty target path", IRREC_ERR_PATH_TRAVERSAL));
        }
        if s.contains("..") || s.contains('\0') {
            return Err(format!("{}: path traversal detected: '{}'", IRREC_ERR_PATH_TRAVERSAL, s));
        }
        Ok(path.to_path_buf())
    }

    /// Computes canonical backup path (`.bak`).
    pub fn backup_path_for(path: &Path) -> PathBuf {
        let mut p = path.to_path_buf().into_os_string();
        p.push(".bak");
        PathBuf::from(p)
    }

    /// Computes unique timestamped quarantine path and prunes excess quarantine files.
    pub fn quarantine_path_for(path: &Path) -> PathBuf {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("runbook_state.json");
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

    /// Prunes older quarantine files exceeding MAX_QUARANTINE_FILES.
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

    /// Validates raw JSON string representing runbook catalog state.
    pub fn validate_runbook_json(content: &str, target_path: &str) -> RunbookValidationReport {
        let now = utcnow_iso();
        if content.len() as u64 > MAX_RUNBOOK_STATE_SIZE {
            return RunbookValidationReport {
                status: RunbookCatalogStatus::Corrupted,
                checked_at_utc: now,
                target_path: target_path.to_string(),
                issues: vec![RunbookValidationIssue {
                    issue_type: RunbookIssueType::OversizedPayload,
                    severity: RunbookIssueSeverity::Critical,
                    message: format!("Payload size {} exceeds limit {}", content.len(), MAX_RUNBOOK_STATE_SIZE),
                    target_id: None,
                }],
                total_runbooks: 0,
                total_active_sessions: 0,
                is_recoverable: true,
            };
        }

        let snapshot: Result<RunbookCatalogSnapshot, serde_json::Error> = serde_json::from_str(content);
        match snapshot {
            Err(e) => RunbookValidationReport {
                status: RunbookCatalogStatus::Corrupted,
                checked_at_utc: now,
                target_path: target_path.to_string(),
                issues: vec![RunbookValidationIssue {
                    issue_type: RunbookIssueType::InvalidJsonSyntax,
                    severity: RunbookIssueSeverity::Critical,
                    message: format!("JSON parse error: {}", e),
                    target_id: None,
                }],
                total_runbooks: 0,
                total_active_sessions: 0,
                is_recoverable: true,
            },
            Ok(cat) => {
                let mut issues = Vec::new();
                let mut seen_ids = HashSet::new();

                for r in &cat.runbooks {
                    if !seen_ids.insert(&r.id) {
                        issues.push(RunbookValidationIssue {
                            issue_type: RunbookIssueType::DuplicateRunbookId,
                            severity: RunbookIssueSeverity::Error,
                            message: format!("Duplicate runbook ID detected: '{}'", r.id),
                            target_id: Some(r.id.clone()),
                        });
                    }
                    if r.steps.is_empty() {
                        issues.push(RunbookValidationIssue {
                            issue_type: RunbookIssueType::CorruptedEntry,
                            severity: RunbookIssueSeverity::Error,
                            message: format!("Runbook '{}' has empty step list", r.id),
                            target_id: Some(r.id.clone()),
                        });
                    }
                }

                let status = if issues.iter().any(|i| i.severity == RunbookIssueSeverity::Critical) {
                    RunbookCatalogStatus::Corrupted
                } else if issues.iter().any(|i| i.severity == RunbookIssueSeverity::Error) {
                    RunbookCatalogStatus::Degraded
                } else {
                    RunbookCatalogStatus::Healthy
                };

                RunbookValidationReport {
                    status,
                    checked_at_utc: now,
                    target_path: target_path.to_string(),
                    issues,
                    total_runbooks: cat.runbooks.len(),
                    total_active_sessions: 0,
                    is_recoverable: true,
                }
            }
        }
    }

    /// Non-destructively inspects state file integrity.
    pub fn validate_state_path(path: &Path) -> RunbookValidationReport {
        let valid_path = match Self::validate_path(path) {
            Ok(p) => p,
            Err(e) => {
                return RunbookValidationReport {
                    status: RunbookCatalogStatus::Corrupted,
                    checked_at_utc: utcnow_iso(),
                    target_path: path.to_string_lossy().to_string(),
                    issues: vec![RunbookValidationIssue {
                        issue_type: RunbookIssueType::InvalidPathTraversal,
                        severity: RunbookIssueSeverity::Critical,
                        message: e,
                        target_id: None,
                    }],
                    total_runbooks: 0,
                    total_active_sessions: 0,
                    is_recoverable: false,
                };
            }
        };

        if !valid_path.exists() {
            return RunbookValidationReport {
                status: RunbookCatalogStatus::Missing,
                checked_at_utc: utcnow_iso(),
                target_path: valid_path.to_string_lossy().to_string(),
                issues: vec![RunbookValidationIssue {
                    issue_type: RunbookIssueType::MissingStateFile,
                    severity: RunbookIssueSeverity::Critical,
                    message: format!("Runbook state file does not exist: {}", valid_path.display()),
                    target_id: None,
                }],
                total_runbooks: 0,
                total_active_sessions: 0,
                is_recoverable: true,
            };
        }

        let metadata = match fs::metadata(&valid_path) {
            Ok(m) => m,
            Err(e) => {
                return RunbookValidationReport {
                    status: RunbookCatalogStatus::Corrupted,
                    checked_at_utc: utcnow_iso(),
                    target_path: valid_path.to_string_lossy().to_string(),
                    issues: vec![RunbookValidationIssue {
                        issue_type: RunbookIssueType::MissingStateFile,
                        severity: RunbookIssueSeverity::Critical,
                        message: format!("Failed reading file metadata: {}", e),
                        target_id: None,
                    }],
                    total_runbooks: 0,
                    total_active_sessions: 0,
                    is_recoverable: true,
                };
            }
        };

        if metadata.len() > MAX_RUNBOOK_STATE_SIZE {
            return RunbookValidationReport {
                status: RunbookCatalogStatus::Corrupted,
                checked_at_utc: utcnow_iso(),
                target_path: valid_path.to_string_lossy().to_string(),
                issues: vec![RunbookValidationIssue {
                    issue_type: RunbookIssueType::OversizedPayload,
                    severity: RunbookIssueSeverity::Critical,
                    message: format!("File size {} exceeds maximum {}", metadata.len(), MAX_RUNBOOK_STATE_SIZE),
                    target_id: None,
                }],
                total_runbooks: 0,
                total_active_sessions: 0,
                is_recoverable: true,
            };
        }

        let content = match fs::read_to_string(&valid_path) {
            Ok(c) => c,
            Err(e) => {
                return RunbookValidationReport {
                    status: RunbookCatalogStatus::Corrupted,
                    checked_at_utc: utcnow_iso(),
                    target_path: valid_path.to_string_lossy().to_string(),
                    issues: vec![RunbookValidationIssue {
                        issue_type: RunbookIssueType::InvalidJsonSyntax,
                        severity: RunbookIssueSeverity::Critical,
                        message: format!("Failed reading file string: {}", e),
                        target_id: None,
                    }],
                    total_runbooks: 0,
                    total_active_sessions: 0,
                    is_recoverable: true,
                };
            }
        };

        Self::validate_runbook_json(&content, &valid_path.to_string_lossy())
    }

    /// Atomically replaces or creates a file using temporary file and atomic rename.
    pub fn atomic_write_file(target: &Path, content: &[u8]) -> Result<(), String> {
        let parent = target.parent().unwrap_or_else(|| Path::new("."));
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("{}: failed creating directory: {}", IRREC_ERR_IO, e))?;
        }

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let fname = target.file_name().and_then(|n| n.to_str()).unwrap_or("state");
        let tmp_path = parent.join(format!(".{}.tmp.{}.{}", fname, pid, nanos));

        if let Err(e) = fs::write(&tmp_path, content) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("{}: failed writing temporary file: {}", IRREC_ERR_IO, e));
        }

        if let Err(e) = fs::rename(&tmp_path, target) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("{}: failed atomic rename: {}", IRREC_ERR_IO, e));
        }

        Ok(())
    }

    /// Quarantines an existing corrupted state file.
    pub fn quarantine_corrupted_file(path: &Path) -> Result<PathBuf, String> {
        let valid_path = Self::validate_path(path)?;
        if !valid_path.exists() {
            return Err(format!("{}: cannot quarantine non-existent file: {}", IRREC_ERR_IO, valid_path.display()));
        }
        let q_path = Self::quarantine_path_for(&valid_path);
        fs::copy(&valid_path, &q_path)
            .map_err(|e| format!("{}: failed copying to quarantine: {}", IRREC_ERR_IO, e))?;
        Ok(q_path)
    }

    /// Creates a `.bak` snapshot backup of the current state.
    pub fn create_backup(path: &Path) -> Result<PathBuf, String> {
        let valid_path = Self::validate_path(path)?;
        if !valid_path.exists() {
            return Err(format!("{}: target file does not exist: {}", IRREC_ERR_IO, valid_path.display()));
        }
        let backup_path = Self::backup_path_for(&valid_path);
        let content = fs::read(&valid_path)
            .map_err(|e| format!("{}: failed reading source: {}", IRREC_ERR_IO, e))?;
        Self::atomic_write_file(&backup_path, &content)?;
        Ok(backup_path)
    }

    /// Restores runbook state from an existing backup snapshot.
    pub fn restore_snapshot(snapshot_path: &Path, target_path: &Path) -> Result<RunbookRecoveryReport, String> {
        let v_snap = Self::validate_path(snapshot_path)?;
        let v_target = Self::validate_path(target_path)?;

        if !v_snap.exists() {
            return Err(format!("{}: snapshot file does not exist: {}", IRREC_ERR_NO_BACKUP, v_snap.display()));
        }

        // Validate snapshot before restoring
        let snap_report = Self::validate_state_path(&v_snap);
        if snap_report.status == RunbookCatalogStatus::Corrupted {
            return Err(format!("{}: snapshot is corrupted: {:?}", IRREC_ERR_VALIDATION, snap_report.issues));
        }

        // Quarantine target if it currently exists and is corrupted
        let q_path = if v_target.exists() {
            Self::quarantine_corrupted_file(&v_target).ok().map(|p| p.to_string_lossy().to_string())
        } else {
            None
        };

        let content = fs::read(&v_snap)
            .map_err(|e| format!("{}: failed reading snapshot: {}", IRREC_ERR_IO, e))?;
        Self::atomic_write_file(&v_target, &content)?;

        Ok(RunbookRecoveryReport {
            ok: true,
            recovered_at_utc: utcnow_iso(),
            quarantine_path: q_path,
            backup_path: Some(v_snap.to_string_lossy().to_string()),
            restored_runbooks_count: snap_report.total_runbooks,
            action_taken: "backup_restored".to_string(),
        })
    }

    /// Repairs runbook state with non-destructive verification, quarantine on corruption, and atomic restoration.
    pub fn repair_runbook_state(path: &Path) -> Result<RunbookRecoveryReport, String> {
        let valid_path = Self::validate_path(path)?;
        let report = Self::validate_state_path(&valid_path);

        match report.status {
            RunbookCatalogStatus::Healthy => Ok(RunbookRecoveryReport {
                ok: true,
                recovered_at_utc: utcnow_iso(),
                quarantine_path: None,
                backup_path: None,
                restored_runbooks_count: report.total_runbooks,
                action_taken: "noop".to_string(),
            }),
            RunbookCatalogStatus::Missing => {
                let canonical = RunbookCatalogSnapshot::canonical_baseline();
                let serialized = serde_json::to_string_pretty(&canonical)
                    .map_err(|e| format!("{}: serialization failed: {}", IRREC_ERR_IO, e))?;
                Self::atomic_write_file(&valid_path, serialized.as_bytes())?;
                Ok(RunbookRecoveryReport {
                    ok: true,
                    recovered_at_utc: utcnow_iso(),
                    quarantine_path: None,
                    backup_path: None,
                    restored_runbooks_count: canonical.runbooks.len(),
                    action_taken: "canonical_reinitialized".to_string(),
                })
            }
            RunbookCatalogStatus::Corrupted | RunbookCatalogStatus::Degraded => {
                // Quarantine corrupted file
                let q_path = Self::quarantine_corrupted_file(&valid_path)
                    .ok()
                    .map(|p| p.to_string_lossy().to_string());

                // Check for valid backup
                let b_path = Self::backup_path_for(&valid_path);
                if b_path.exists() {
                    let b_report = Self::validate_state_path(&b_path);
                    if b_report.status == RunbookCatalogStatus::Healthy {
                        let content = fs::read(&b_path)
                            .map_err(|e| format!("{}: failed reading backup: {}", IRREC_ERR_IO, e))?;
                        Self::atomic_write_file(&valid_path, &content)?;
                        return Ok(RunbookRecoveryReport {
                            ok: true,
                            recovered_at_utc: utcnow_iso(),
                            quarantine_path: q_path,
                            backup_path: Some(b_path.to_string_lossy().to_string()),
                            restored_runbooks_count: b_report.total_runbooks,
                            action_taken: "backup_restored".to_string(),
                        });
                    }
                }

                // Fall back to canonical baseline
                let canonical = RunbookCatalogSnapshot::canonical_baseline();
                let serialized = serde_json::to_string_pretty(&canonical)
                    .map_err(|e| format!("{}: serialization failed: {}", IRREC_ERR_IO, e))?;
                Self::atomic_write_file(&valid_path, serialized.as_bytes())?;
                Ok(RunbookRecoveryReport {
                    ok: true,
                    recovered_at_utc: utcnow_iso(),
                    quarantine_path: q_path,
                    backup_path: None,
                    restored_runbooks_count: canonical.runbooks.len(),
                    action_taken: "canonical_reinitialized".to_string(),
                })
            }
        }
    }

    /// Safe envelope wrapper for state path validation.
    pub fn validate_state_path_safe(path: &Path) -> RunbookRecoveryResultEnvelope<RunbookValidationReport> {
        let rep = Self::validate_state_path(path);
        if rep.status == RunbookCatalogStatus::Healthy {
            RunbookRecoveryResultEnvelope::success(rep)
        } else {
            RunbookRecoveryResultEnvelope {
                ok: false,
                data: Some(rep),
                error_code: Some("IRREC_ERR_UNHEALTHY".to_string()),
                error_message: Some("State validation detected issues".to_string()),
                audit_row_required: true,
            }
        }
    }

    /// Safe envelope wrapper for repair operations.
    pub fn repair_runbook_state_safe(path: &Path) -> RunbookRecoveryResultEnvelope<RunbookRecoveryReport> {
        match Self::repair_runbook_state(path) {
            Ok(rep) => RunbookRecoveryResultEnvelope::success(rep),
            Err(e) => RunbookRecoveryResultEnvelope::failure(IRREC_ERR_VALIDATION, &e),
        }
    }

    /// Safe envelope wrapper for backup snapshot creation.
    pub fn create_backup_safe(path: &Path) -> RunbookRecoveryResultEnvelope<String> {
        match Self::create_backup(path) {
            Ok(p) => RunbookRecoveryResultEnvelope::success(p.to_string_lossy().to_string()),
            Err(e) => RunbookRecoveryResultEnvelope::failure(IRREC_ERR_IO, &e),
        }
    }

    /// Safe envelope wrapper for snapshot restoration.
    pub fn restore_snapshot_safe(snapshot_path: &Path, target_path: &Path) -> RunbookRecoveryResultEnvelope<RunbookRecoveryReport> {
        match Self::restore_snapshot(snapshot_path, target_path) {
            Ok(rep) => RunbookRecoveryResultEnvelope::success(rep),
            Err(e) => RunbookRecoveryResultEnvelope::failure(IRREC_ERR_VALIDATION, &e),
        }
    }
}
