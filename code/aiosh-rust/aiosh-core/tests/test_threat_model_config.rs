//! Unit tests for Threat Model Configuration Subsystem (T-02745).

use aiosh_core::threat_model_config::*;
use std::path::PathBuf;
use tempfile::tempdir;

#[test]
fn test_threat_model_config_defaults() {
    let cfg = ThreatModelConfig::default();
    assert_eq!(cfg.version, "1.0.0");
    assert_eq!(cfg.store_path, PathBuf::from(DEFAULT_THREAT_STORE_PATH));
    assert_eq!(cfg.max_threat_capacity, DEFAULT_MAX_THREAT_CAPACITY);
    assert_eq!(cfg.max_store_file_bytes, DEFAULT_MAX_STORE_FILE_BYTES);
    assert!(cfg.enforce_strict_transitions);
    assert!(cfg.require_mitigation_for_status);
    assert!(cfg.enable_private_key_scrubbing);
    assert!(cfg.audit_all_queries);
    assert!(cfg.audit_all_mutations);
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_threat_model_config_bounds_validation() {
    let mut cfg = ThreatModelConfig::default();

    // Invalid version
    cfg.version = "2.0.0".into();
    assert!(cfg.validate().is_err());
    cfg.version = "".into();
    assert!(cfg.validate().is_err());
    cfg.version = "1.0.0".into();

    // Traversal in store_path
    cfg.store_path = PathBuf::from("../etc/threats.json");
    let err = cfg.validate().unwrap_err();
    assert!(err.contains(THREATCONF_ERR_VALIDATION));
    cfg.store_path = PathBuf::from(DEFAULT_THREAT_STORE_PATH);

    // Empty store_path
    cfg.store_path = PathBuf::from("");
    assert!(cfg.validate().unwrap_err().contains(THREATCONF_ERR_VALIDATION));
    cfg.store_path = PathBuf::from(DEFAULT_THREAT_STORE_PATH);

    // Capacity bounds
    cfg.max_threat_capacity = 0;
    assert!(cfg.validate().unwrap_err().contains(THREATCONF_ERR_BOUNDS));
    cfg.max_threat_capacity = 10000;
    assert!(cfg.validate().unwrap_err().contains(THREATCONF_ERR_BOUNDS));
    cfg.max_threat_capacity = 256;
    assert!(cfg.validate().is_ok());

    // Store file size bounds
    cfg.max_store_file_bytes = 100;
    assert!(cfg.validate().unwrap_err().contains(THREATCONF_ERR_BOUNDS));
    cfg.max_store_file_bytes = 50000000;
    assert!(cfg.validate().unwrap_err().contains(THREATCONF_ERR_BOUNDS));
    cfg.max_store_file_bytes = 2097152;
    assert!(cfg.validate().is_ok());
}

#[test]
fn test_threat_model_config_save_and_load() {
    let dir = tempdir().unwrap();
    let cfg_path = dir.path().join("sub/threat_model_config.json");

    let mut cfg = ThreatModelConfig::default();
    cfg.max_threat_capacity = 1000;
    cfg.enforce_strict_transitions = true;
    cfg.audit_all_queries = false;

    assert!(cfg.save_to_path(&cfg_path).is_ok());
    assert!(cfg_path.exists());

    let loaded = ThreatModelConfig::load_from_path(&cfg_path).unwrap();
    assert_eq!(loaded.max_threat_capacity, 1000);
    assert_eq!(loaded.enforce_strict_transitions, true);
    assert_eq!(loaded.audit_all_queries, false);
}

#[test]
fn test_threat_model_config_env_overrides() {
    std::env::set_var("AIOS_THREAT_MODEL_PATH", "custom/threats.json");
    std::env::set_var("AIOS_THREAT_CAPACITY", "777");

    let cfg = ThreatModelConfig::from_env();
    assert_eq!(cfg.store_path, PathBuf::from("custom/threats.json"));
    assert_eq!(cfg.max_threat_capacity, 777);

    std::env::remove_var("AIOS_THREAT_MODEL_PATH");
    std::env::remove_var("AIOS_THREAT_CAPACITY");
}

#[test]
fn test_threat_model_config_rejections() {
    let dir = tempdir().unwrap();

    // 1. Non-existent file
    let missing_path = dir.path().join("nonexistent.json");
    let res_missing = ThreatModelConfig::load_from_path(&missing_path);
    assert!(res_missing.is_err());
    assert!(res_missing.unwrap_err().contains(THREATCONF_ERR_IO));

    // 2. Oversized config file (> 64 KiB)
    let oversized_path = dir.path().join("oversized.json");
    let huge_data = "x".repeat(65536 + 10);
    std::fs::write(&oversized_path, huge_data).unwrap();
    let res_oversized = ThreatModelConfig::load_from_path(&oversized_path);
    assert!(res_oversized.is_err());
    assert!(res_oversized.unwrap_err().contains(THREATCONF_ERR_BOUNDS));

    // 3. Malformed JSON
    let malformed_path = dir.path().join("malformed.json");
    std::fs::write(&malformed_path, "{ broken json:").unwrap();
    let res_malformed = ThreatModelConfig::load_from_path(&malformed_path);
    assert!(res_malformed.is_err());
    assert!(res_malformed.unwrap_err().contains(THREATCONF_ERR_PARSE));
}

#[test]
fn test_threat_model_config_hardening() {
    let dir = tempdir().unwrap();

    // 1. Validation rejection prevents file creation
    let mut invalid_cfg = ThreatModelConfig::default();
    invalid_cfg.max_threat_capacity = 999999;
    let target_path = dir.path().join("invalid_cfg.json");
    let res_save = invalid_cfg.save_to_path(&target_path);
    assert!(res_save.is_err());
    assert!(!target_path.exists());

    // 2. Zero leftover tempfiles after save
    let valid_cfg = ThreatModelConfig::default();
    let valid_path = dir.path().join("valid_cfg.json");
    assert!(valid_cfg.save_to_path(&valid_path).is_ok());
    assert!(valid_path.exists());

    // Ensure no .tmp files exist in directory
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        let fname = entry.file_name().to_string_lossy().to_string();
        assert!(!fname.contains("tmp"), "Leaked temporary file found: {}", fname);
    }

    // 3. Control character rejection
    let mut ctrl_cfg = ThreatModelConfig::default();
    ctrl_cfg.store_path = PathBuf::from("threats\0bad.json");
    assert!(ctrl_cfg.validate().is_err());

    // 4. Overly long path rejection (> 1024 chars)
    let mut long_cfg = ThreatModelConfig::default();
    long_cfg.store_path = PathBuf::from("a/".repeat(600) + "threats.json");
    assert!(long_cfg.validate().is_err());
}
