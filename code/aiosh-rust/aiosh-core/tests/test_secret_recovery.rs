//! Unit Tests for Secrets Handling Recovery & Validation (T-02695).

use std::collections::HashMap;
use std::fs;
use aiosh_core::secret_data_model::{SecretKind, SecretMetadata, SecretScope, SecretState};
use aiosh_core::secret_recovery::*;
use aiosh_core::secret_service::{StoredSecretRecord, VaultPayload, hex_encode};

fn create_sample_vault_record(id: &str, value: &str) -> StoredSecretRecord {
    let hex = hex_encode(value.as_bytes());
    StoredSecretRecord {
        metadata: SecretMetadata {
            id: id.to_string(),
            name: format!("Name-{}", id),
            description: "Test secret".to_string(),
            kind: SecretKind::ApiKey,
            scope: SecretScope::Global,
            state: SecretState::Active,
            version: 1,
            fingerprint: "0123456789abcdef".to_string(),
            created_at: "2026-10-03T00:00:00Z".to_string(),
            updated_at: "2026-10-03T00:00:00Z".to_string(),
            expires_at: None,
            labels: HashMap::new(),
        },
        payload_hex: hex,
    }
}

#[test]
fn test_secret_recovery_path_validation() {
    assert!(SecretRecoveryService::validate_path(std::path::Path::new("vault.json")).is_ok());
    assert!(SecretRecoveryService::validate_path(std::path::Path::new("../vault.json")).is_err());
    assert!(SecretRecoveryService::validate_path(std::path::Path::new("vault\0.json")).is_err());
}

#[test]
fn test_secret_recovery_validate_missing_and_corrupt() {
    let tmp_dir = std::env::temp_dir().join("test_sec_rec_missing");
    let _ = fs::create_dir_all(&tmp_dir);
    let vault_path = tmp_dir.join("missing_vault.json");
    let _ = fs::remove_file(&vault_path);

    // 1. Missing file
    let rep_missing = SecretRecoveryService::validate_vault(&vault_path).expect("validate missing");
    assert_eq!(rep_missing.status, SecretVaultStatus::Missing);

    // 2. Corrupted JSON file
    fs::write(&vault_path, "{ broken json ...").expect("write broken");
    let rep_corrupt = SecretRecoveryService::validate_vault(&vault_path).expect("validate corrupt");
    assert_eq!(rep_corrupt.status, SecretVaultStatus::Corrupted);
    assert!(rep_corrupt.issues.iter().any(|i| i.issue_type == "InvalidJson"));

    // 3. Invalid Hex in record
    let mut secrets = HashMap::new();
    let mut rec = create_sample_vault_record("bad_hex", "val");
    rec.payload_hex = "invalid_hex_string_zzz".into();
    secrets.insert("bad_hex".into(), rec);
    let payload = VaultPayload {
        version: "1.0".into(),
        secrets,
    };
    fs::write(&vault_path, serde_json::to_string_pretty(&payload).unwrap()).expect("write bad hex");
    let rep_hex = SecretRecoveryService::validate_vault(&vault_path).expect("validate bad hex");
    assert_eq!(rep_hex.status, SecretVaultStatus::Corrupted);
    assert!(rep_hex.issues.iter().any(|i| i.issue_type == "CorruptedPayloadHex"));

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_secret_recovery_backup_and_restore() {
    let tmp_dir = std::env::temp_dir().join("test_sec_rec_backup");
    let _ = fs::create_dir_all(&tmp_dir);
    let vault_path = tmp_dir.join("vault.json");

    let mut secrets = HashMap::new();
    secrets.insert("sec1".into(), create_sample_vault_record("sec1", "super_secret"));
    let payload = VaultPayload {
        version: "1.0".into(),
        secrets,
    };
    fs::write(&vault_path, serde_json::to_string_pretty(&payload).unwrap()).expect("write vault");

    // Create backup
    let bak_path = SecretRecoveryService::create_backup(&vault_path).expect("create backup");
    assert!(bak_path.exists());

    // Corrupt active vault
    fs::write(&vault_path, "corrupted content").expect("corrupt vault");
    let check = SecretRecoveryService::validate_vault(&vault_path).expect("validate");
    assert_eq!(check.status, SecretVaultStatus::Corrupted);

    // Restore from backup
    let restore_rep = SecretRecoveryService::restore_from_backup(&vault_path).expect("restore");
    assert!(restore_rep.success);
    assert_eq!(restore_rep.records_recovered, 1);

    // Vault is healthy again
    let check2 = SecretRecoveryService::validate_vault(&vault_path).expect("validate after restore");
    assert_eq!(check2.status, SecretVaultStatus::Healthy);
    assert_eq!(check2.valid_records, 1);

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_secret_recovery_repair_quarantine() {
    let tmp_dir = std::env::temp_dir().join("test_sec_rec_repair");
    let _ = fs::create_dir_all(&tmp_dir);
    let vault_path = tmp_dir.join("vault.json");

    let mut secrets = HashMap::new();
    secrets.insert("good_rec".into(), create_sample_vault_record("good_rec", "valid_payload"));
    let mut bad_rec = create_sample_vault_record("bad_rec", "foo");
    bad_rec.payload_hex = "invalid_hex!!".into();
    secrets.insert("bad_rec".into(), bad_rec);

    let payload = VaultPayload {
        version: "1.0".into(),
        secrets,
    };
    fs::write(&vault_path, serde_json::to_string_pretty(&payload).unwrap()).expect("write mixed vault");

    let rep_before = SecretRecoveryService::validate_vault(&vault_path).expect("validate before");
    assert_eq!(rep_before.status, SecretVaultStatus::Corrupted);
    assert_eq!(rep_before.corrupted_records, 1);
    assert_eq!(rep_before.valid_records, 1);

    // Run repair with quarantine
    let repair_rep = SecretRecoveryService::repair_vault(&vault_path, true).expect("repair vault");
    assert!(repair_rep.success);
    assert_eq!(repair_rep.records_recovered, 1);
    assert_eq!(repair_rep.records_dropped, 1);
    assert!(repair_rep.quarantined_path.is_some());

    // Validate repaired vault is now Healthy
    let rep_after = SecretRecoveryService::validate_vault(&vault_path).expect("validate after");
    assert_eq!(rep_after.status, SecretVaultStatus::Healthy);
    assert_eq!(rep_after.valid_records, 1);
    assert_eq!(rep_after.corrupted_records, 0);

    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_secret_recovery_hardening() {
    // 1. Rejection of UNC paths
    assert!(SecretRecoveryService::validate_path(std::path::Path::new("\\\\evil_server\\share\\vault.json")).is_err());
    assert!(SecretRecoveryService::validate_path(std::path::Path::new("//evil_server/share/vault.json")).is_err());

    // 2. Quarantine payload scrubbing
    let tmp_dir = std::env::temp_dir().join("test_sec_rec_hardening");
    let _ = fs::create_dir_all(&tmp_dir);
    let vault_path = tmp_dir.join("vault.json");

    let mut secrets = HashMap::new();
    let mut bad_rec = create_sample_vault_record("bad_rec", "secret_to_scrub");
    bad_rec.payload_hex = "invalid_hex!!".into();
    secrets.insert("bad_rec".into(), bad_rec);

    let payload = VaultPayload {
        version: "1.0".into(),
        secrets,
    };
    fs::write(&vault_path, serde_json::to_string_pretty(&payload).unwrap()).expect("write bad vault");

    let rep = SecretRecoveryService::repair_vault(&vault_path, true).expect("repair vault");
    let q_path = rep.quarantined_path.expect("quarantine path present");
    let q_content = fs::read_to_string(&q_path).expect("read quarantine");
    assert!(q_content.contains("[SCRUBBED_ON_QUARANTINE]"));
    assert!(!q_content.contains("invalid_hex!!"));

    let _ = fs::remove_dir_all(&tmp_dir);
}
