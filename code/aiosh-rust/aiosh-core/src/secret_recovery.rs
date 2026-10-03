//! Secrets Handling Recovery & Validation Subsystem (SECREC1..SECREC5).
//!
//! Provides integrity checking, snapshot backups, crash-consistent repair,
//! and validation reporting for the runtime secrets vault.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::canonical::utcnow_iso;
use crate::secret_service::{StoredSecretRecord, VaultPayload, hex_decode, MAX_SECRETS_STORE_SIZE};

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

    pub fn validate_vault(path: &Path) -> Result<SecretIntegrityReport, String> {
        let valid_path = Self::validate_path(path)?;
        let p_str = valid_path.to_string_lossy().to_string();
        let backup_path = Self::backup_path_for(&valid_path);
        let has_backup = backup_path.exists();
        let backup_path_str = if has_backup {
            Some(backup_path.to_string_lossy().to_string())
        } else {
            None
        };

        if !valid_path.exists() {
            return Ok(SecretIntegrityReport {
                vault_path: p_str,
                status: SecretVaultStatus::Missing,
                total_records: 0,
                valid_records: 0,
                corrupted_records: 0,
                issues: vec![SecretIntegrityIssue {
                    severity: SecretIssueSeverity::Warning,
                    issue_type: "FileNotFound".into(),
                    secret_id: None,
                    details: "Vault store file does not exist".into(),
                }],
                has_backup,
                backup_path: backup_path_str,
                timestamp: utcnow_iso(),
            });
        }

        let metadata = fs::metadata(&valid_path)
            .map_err(|e| format!("{}: Failed to read metadata: {}", SECREC_ERR_IO, e))?;
        if metadata.len() > MAX_SECRETS_STORE_SIZE {
            return Ok(SecretIntegrityReport {
                vault_path: p_str,
                status: SecretVaultStatus::Corrupted,
                total_records: 0,
                valid_records: 0,
                corrupted_records: 0,
                issues: vec![SecretIntegrityIssue {
                    severity: SecretIssueSeverity::Critical,
                    issue_type: "FileSizeExceeded".into(),
                    secret_id: None,
                    details: format!("Vault file size {} exceeds max allowed limit {}", metadata.len(), MAX_SECRETS_STORE_SIZE),
                }],
                has_backup,
                backup_path: backup_path_str,
                timestamp: utcnow_iso(),
            });
        }

        let content = fs::read_to_string(&valid_path)
            .map_err(|e| format!("{}: Failed to read vault file: {}", SECREC_ERR_IO, e))?;

        let parsed: Result<VaultPayload, serde_json::Error> = serde_json::from_str(&content);
        let mut issues = Vec::new();

        match parsed {
            Ok(payload) => {
                let total = payload.secrets.len();
                let mut valid_count = 0;
                let mut corrupt_count = 0;

                for (key, record) in payload.secrets {
                    let mut record_ok = true;

                    if key != record.metadata.id {
                        issues.push(SecretIntegrityIssue {
                            severity: SecretIssueSeverity::Error,
                            issue_type: "KeyMismatch".into(),
                            secret_id: Some(record.metadata.id.clone()),
                            details: format!("Map key '{}' does not match record metadata id '{}'", key, record.metadata.id),
                        });
                        record_ok = false;
                    }

                    if record.metadata.id.trim().is_empty() || record.metadata.id.len() > 64 {
                        issues.push(SecretIntegrityIssue {
                            severity: SecretIssueSeverity::Error,
                            issue_type: "InvalidId".into(),
                            secret_id: Some(record.metadata.id.clone()),
                            details: "Secret ID length is invalid or empty".into(),
                        });
                        record_ok = false;
                    }

                    if hex_decode(&record.payload_hex).is_err() {
                        issues.push(SecretIntegrityIssue {
                            severity: SecretIssueSeverity::Critical,
                            issue_type: "CorruptedPayloadHex".into(),
                            secret_id: Some(record.metadata.id.clone()),
                            details: "Secret payload hex encoding is invalid".into(),
                        });
                        record_ok = false;
                    }

                    if record.metadata.state == crate::secret_data_model::SecretState::Revoked {
                        issues.push(SecretIntegrityIssue {
                            severity: SecretIssueSeverity::Warning,
                            issue_type: "RevokedSecret".into(),
                            secret_id: Some(record.metadata.id.clone()),
                            details: "Secret entry is revoked".into(),
                        });
                    }

                    if record_ok {
                        valid_count += 1;
                    } else {
                        corrupt_count += 1;
                    }
                }

                let status = if corrupt_count > 0 {
                    SecretVaultStatus::Corrupted
                } else if !issues.is_empty() {
                    SecretVaultStatus::Degraded
                } else {
                    SecretVaultStatus::Healthy
                };

                Ok(SecretIntegrityReport {
                    vault_path: p_str,
                    status,
                    total_records: total,
                    valid_records: valid_count,
                    corrupted_records: corrupt_count,
                    issues,
                    has_backup,
                    backup_path: backup_path_str,
                    timestamp: utcnow_iso(),
                })
            }
            Err(e) => {
                issues.push(SecretIntegrityIssue {
                    severity: SecretIssueSeverity::Critical,
                    issue_type: "InvalidJson".into(),
                    secret_id: None,
                    details: format!("JSON parsing failure: {}", e),
                });

                Ok(SecretIntegrityReport {
                    vault_path: p_str,
                    status: SecretVaultStatus::Corrupted,
                    total_records: 0,
                    valid_records: 0,
                    corrupted_records: 0,
                    issues,
                    has_backup,
                    backup_path: backup_path_str,
                    timestamp: utcnow_iso(),
                })
            }
        }
    }

    pub fn create_backup(path: &Path) -> Result<PathBuf, String> {
        let valid_path = Self::validate_path(path)?;
        if !valid_path.exists() {
            return Err(format!("{}: Target vault file does not exist: {}", SECREC_ERR_IO, valid_path.display()));
        }

        let backup_path = Self::backup_path_for(&valid_path);
        let tmp_backup = backup_path.with_extension("tmp.bak");

        let bytes = fs::read(&valid_path)
            .map_err(|e| format!("{}: Failed reading source vault: {}", SECREC_ERR_IO, e))?;
        fs::write(&tmp_backup, &bytes)
            .map_err(|e| format!("{}: Failed writing backup tmp: {}", SECREC_ERR_IO, e))?;
        fs::rename(&tmp_backup, &backup_path)
            .map_err(|e| format!("{}: Failed atomic rename of backup: {}", SECREC_ERR_IO, e))?;

        Ok(backup_path)
    }

    pub fn restore_from_backup(path: &Path) -> Result<SecretRecoveryReport, String> {
        let valid_path = Self::validate_path(path)?;
        let backup_path = Self::backup_path_for(&valid_path);

        if !backup_path.exists() {
            return Err(format!("{}: Backup file '{}' does not exist", SECREC_ERR_BACKUP_NOT_FOUND, backup_path.display()));
        }

        let backup_report = Self::validate_vault(&backup_path)?;
        if backup_report.status == SecretVaultStatus::Corrupted {
            return Err(format!("{}: Backup file is itself corrupted; refusal to overwrite", SECREC_ERR_CORRUPT));
        }

        let tmp_restore = valid_path.with_extension("tmp.restore");
        let bytes = fs::read(&backup_path)
            .map_err(|e| format!("{}: Failed reading backup: {}", SECREC_ERR_IO, e))?;
        fs::write(&tmp_restore, &bytes)
            .map_err(|e| format!("{}: Failed writing restore tmp: {}", SECREC_ERR_IO, e))?;
        fs::rename(&tmp_restore, &valid_path)
            .map_err(|e| format!("{}: Failed atomic restore rename: {}", SECREC_ERR_IO, e))?;

        Ok(SecretRecoveryReport {
            vault_path: valid_path.to_string_lossy().to_string(),
            success: true,
            actions: vec![SecretRecoveryAction {
                action_type: "RestoredFromBackup".into(),
                target_id: None,
                description: format!("Vault restored from backup snapshot '{}'", backup_path.display()),
            }],
            records_recovered: backup_report.valid_records,
            records_dropped: 0,
            quarantined_path: None,
            timestamp: utcnow_iso(),
        })
    }

    pub fn repair_vault(path: &Path, quarantine: bool) -> Result<SecretRecoveryReport, String> {
        let valid_path = Self::validate_path(path)?;
        if !valid_path.exists() {
            return Err(format!("{}: File does not exist to repair", SECREC_ERR_IO));
        }

        let report = Self::validate_vault(&valid_path)?;
        if report.status == SecretVaultStatus::Healthy {
            return Ok(SecretRecoveryReport {
                vault_path: valid_path.to_string_lossy().to_string(),
                success: true,
                actions: vec![SecretRecoveryAction {
                    action_type: "NoActionNeeded".into(),
                    target_id: None,
                    description: "Vault is already healthy".into(),
                }],
                records_recovered: report.valid_records,
                records_dropped: 0,
                quarantined_path: None,
                timestamp: utcnow_iso(),
            });
        }

        let content = fs::read_to_string(&valid_path)
            .map_err(|e| format!("{}: Failed to read vault file: {}", SECREC_ERR_IO, e))?;

        let mut actions = Vec::new();
        let mut quarantined_path_str = None;
        let mut recovered_count = 0;
        let mut dropped_count = 0;

        match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(json_val) => {
                let mut clean_secrets: HashMap<String, StoredSecretRecord> = HashMap::new();
                let mut corrupt_records: Vec<serde_json::Value> = Vec::new();

                if let Some(secrets_map) = json_val.get("secrets").and_then(|v| v.as_object()) {
                    for (k, v) in secrets_map {
                        match serde_json::from_value::<StoredSecretRecord>(v.clone()) {
                            Ok(rec) => {
                                if hex_decode(&rec.payload_hex).is_ok() && !rec.metadata.id.is_empty() {
                                    clean_secrets.insert(rec.metadata.id.clone(), rec);
                                    recovered_count += 1;
                                } else {
                                    dropped_count += 1;
                                    corrupt_records.push(v.clone());
                                    actions.push(SecretRecoveryAction {
                                        action_type: "DroppedCorruptedRecord".into(),
                                        target_id: Some(k.clone()),
                                        description: "Dropped record due to invalid hex or empty ID".into(),
                                    });
                                }
                            }
                            Err(_) => {
                                dropped_count += 1;
                                corrupt_records.push(v.clone());
                                actions.push(SecretRecoveryAction {
                                    action_type: "DroppedMalformedRecord".into(),
                                    target_id: Some(k.clone()),
                                    description: "Record failed StoredSecretRecord deserialization".into(),
                                });
                            }
                        }
                    }
                }

                if quarantine && !corrupt_records.is_empty() {
                    let ts_suffix = utcnow_iso().replace([':', '-'], "");
                    let q_path = valid_path.with_extension(format!("corrupt.{}.json", ts_suffix));
                    let q_json = serde_json::to_string_pretty(&corrupt_records)
                        .unwrap_or_else(|_| "[]".into());
                    let _ = fs::write(&q_path, q_json);
                    quarantined_path_str = Some(q_path.to_string_lossy().to_string());
                    actions.push(SecretRecoveryAction {
                        action_type: "QuarantinedRecords".into(),
                        target_id: None,
                        description: format!("Quarantined {} corrupt records", corrupt_records.len()),
                    });
                }

                let new_payload = VaultPayload {
                    version: "1.0".into(),
                    secrets: clean_secrets,
                };

                let tmp_path = valid_path.with_extension("tmp.repair");
                let clean_json = serde_json::to_string_pretty(&new_payload)
                    .map_err(|e| format!("{}: Serialization error: {}", SECREC_ERR_IO, e))?;
                fs::write(&tmp_path, clean_json)
                    .map_err(|e| format!("{}: Failed writing repair tmp: {}", SECREC_ERR_IO, e))?;
                fs::rename(&tmp_path, &valid_path)
                    .map_err(|e| format!("{}: Failed atomic rename repair: {}", SECREC_ERR_IO, e))?;

                actions.push(SecretRecoveryAction {
                    action_type: "RegeneratedVault".into(),
                    target_id: None,
                    description: format!("Vault rewritten with {} valid records", recovered_count),
                });

                Ok(SecretRecoveryReport {
                    vault_path: valid_path.to_string_lossy().to_string(),
                    success: true,
                    actions,
                    records_recovered: recovered_count,
                    records_dropped: dropped_count,
                    quarantined_path: quarantined_path_str,
                    timestamp: utcnow_iso(),
                })
            }
            Err(_) => {
                let backup_path = Self::backup_path_for(&valid_path);
                if backup_path.exists() {
                    let res = Self::restore_from_backup(&valid_path)?;
                    Ok(res)
                } else {
                    let new_payload = VaultPayload {
                        version: "1.0".into(),
                        secrets: HashMap::new(),
                    };
                    let tmp_path = valid_path.with_extension("tmp.repair");
                    let clean_json = serde_json::to_string_pretty(&new_payload)
                        .map_err(|e| format!("{}: Serialization error: {}", SECREC_ERR_IO, e))?;
                    fs::write(&tmp_path, clean_json)
                        .map_err(|e| format!("{}: Failed writing repair tmp: {}", SECREC_ERR_IO, e))?;
                    fs::rename(&tmp_path, &valid_path)
                        .map_err(|e| format!("{}: Failed atomic rename repair: {}", SECREC_ERR_IO, e))?;

                    Ok(SecretRecoveryReport {
                        vault_path: valid_path.to_string_lossy().to_string(),
                        success: true,
                        actions: vec![SecretRecoveryAction {
                            action_type: "ReinitializedEmptyVault".into(),
                            target_id: None,
                            description: "Unparseable vault replaced with empty valid vault".into(),
                        }],
                        records_recovered: 0,
                        records_dropped: 0,
                        quarantined_path: None,
                        timestamp: utcnow_iso(),
                    })
                }
            }
        }
    }
}
