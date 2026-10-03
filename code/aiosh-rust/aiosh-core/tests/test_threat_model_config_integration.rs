//! Integration tests for Threat Model Configuration Subsystem (T-02746).

use aiosh_core::threat_model_config::*;
use aiosh_core::threat_model_data_model::*;
use aiosh_core::threat_model_service::*;
use tempfile::tempdir;

#[test]
fn test_threat_model_config_service_integration() {
    let dir = tempdir().unwrap();
    let cfg_path = dir.path().join("threat_config.json");
    let store_path = dir.path().join("custom_threats.json");

    // 1. Create and save custom configuration
    let mut config = ThreatModelConfig::default();
    config.store_path = store_path.clone();
    config.max_threat_capacity = 3; // small capacity to test boundary enforcement
    assert!(config.save_to_path(&cfg_path).is_ok());

    // 2. Initialize ThreatModelService from configuration
    let loaded_cfg = ThreatModelConfig::load_from_path(&cfg_path).expect("load config");
    let mut svc = ThreatModelService::from_config(&loaded_cfg).expect("init service from config");
    assert_eq!(svc.list_threats().len(), 0);

    // 3. Register threats through configured service
    let t1 = ThreatEntry::new(
        "THREAT-CFG-01",
        "Config Invariant Breach",
        "Adversary attempts to manipulate threat catalog configuration",
        ThreatCategory::Tampering,
        ThreatSeverity::High,
        "config_engine",
        vec!["CWE-15".into()],
        vec!["Enforce strict schema bounds".into()],
    ).unwrap();
    assert!(svc.register_threat(t1).is_ok());

    let t2 = ThreatEntry::new(
        "THREAT-CFG-02",
        "Unauthorized Status Elevation",
        "Adversary attempts to force status transition without mitigation",
        ThreatCategory::ElevationOfPrivilege,
        ThreatSeverity::Critical,
        "pep_gate",
        vec!["CWE-284".into()],
        vec!["Enforce cryptographic PEP authorization".into()],
    ).unwrap();
    assert!(svc.register_threat(t2).is_ok());

    // 4. Save through service and reload via another service instance
    assert!(svc.save_to_path(&store_path).is_ok());
    assert!(store_path.exists());

    let reloaded_svc = ThreatModelService::from_config(&loaded_cfg).expect("reload service from config");
    assert_eq!(reloaded_svc.list_threats().len(), 2);
    assert!(reloaded_svc.get_threat("THREAT-CFG-01").is_some());
    assert!(reloaded_svc.get_threat("THREAT-CFG-02").is_some());

    // 5. Verify risk assessment calculation on configured catalog
    let assess = reloaded_svc.assess_risk();
    assert_eq!(assess.total_threats, 2);
    assert!(assess.overall_risk_score > 0);
}
