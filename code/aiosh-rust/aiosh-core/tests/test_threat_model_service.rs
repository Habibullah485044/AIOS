//! Unit Tests for Threat Model Core Service (T-02715).

use std::fs;
use aiosh_core::threat_model_data_model::*;
use aiosh_core::threat_model_service::*;

#[test]
fn test_threat_service_initialization_and_canonical_threats() {
    let svc = ThreatModelService::with_canonical_threats();
    let threats = svc.list_threats();
    assert_eq!(threats.len(), 7);

    // Verify all STRIDE categories covered
    assert!(threats.iter().any(|t| t.category == ThreatCategory::Spoofing));
    assert!(threats.iter().any(|t| t.category == ThreatCategory::Tampering));
    assert!(threats.iter().any(|t| t.category == ThreatCategory::Repudiation));
    assert!(threats.iter().any(|t| t.category == ThreatCategory::InformationDisclosure));
    assert!(threats.iter().any(|t| t.category == ThreatCategory::DenialOfService));
    assert!(threats.iter().any(|t| t.category == ThreatCategory::ElevationOfPrivilege));
    assert!(threats.iter().any(|t| t.category == ThreatCategory::SupplyChainRisk));

    // Verify all baseline threats are mitigated
    for t in threats {
        assert_eq!(t.status, ThreatStatus::Mitigated);
        assert!(!t.mitigations.is_empty());
    }
}

#[test]
fn test_threat_service_lifecycle_operations() {
    let mut svc = ThreatModelService::new();

    let entry = ThreatEntry::new(
        "THREAT-TEST-01",
        "Test Threat",
        "Test description",
        ThreatCategory::Tampering,
        ThreatSeverity::High,
        "test_component",
        vec!["CWE-20".into()],
        vec![],
    ).expect("valid threat");

    // Register
    assert!(svc.register_threat(entry).is_ok());
    assert_eq!(svc.list_threats().len(), 1);

    // Duplicate fails
    let dup = ThreatEntry::new(
        "THREAT-TEST-01",
        "Duplicate",
        "Desc",
        ThreatCategory::Tampering,
        ThreatSeverity::Low,
        "test_comp",
        vec![],
        vec![],
    ).unwrap();
    assert!(svc.register_threat(dup).is_err());

    // Get
    let retrieved = svc.get_threat("THREAT-TEST-01").expect("found");
    assert_eq!(retrieved.title, "Test Threat");

    // Status transition: Identified -> UnderReview
    assert!(svc.update_status("THREAT-TEST-01", ThreatStatus::UnderReview).is_ok());
    assert_eq!(svc.get_threat("THREAT-TEST-01").unwrap().status, ThreatStatus::UnderReview);

    // Transition to Mitigated without mitigations fails
    assert!(svc.update_status("THREAT-TEST-01", ThreatStatus::Mitigated).is_err());

    // Attach mitigation
    assert!(svc.attach_mitigation("THREAT-TEST-01", "Implement strict bounds validation").is_ok());

    // Transition to Mitigated now succeeds
    assert!(svc.update_status("THREAT-TEST-01", ThreatStatus::Mitigated).is_ok());
    assert_eq!(svc.get_threat("THREAT-TEST-01").unwrap().status, ThreatStatus::Mitigated);
}

#[test]
fn test_threat_service_risk_assessment() {
    let mut svc = ThreatModelService::with_canonical_threats();

    // Baseline assessment with all 7 mitigated threats
    let report_initial = svc.assess_risk();
    assert_eq!(report_initial.total_threats, 7);
    assert_eq!(report_initial.mitigated_count, 7);
    assert_eq!(report_initial.critical_unmitigated_count, 0);
    assert_eq!(report_initial.overall_risk_score, 0);

    // Add unmitigated critical threat
    let critical_threat = ThreatEntry::new(
        "THREAT-CRIT-NEW",
        "Unmitigated Kernel Bug",
        "Memory corruption in kernel module",
        ThreatCategory::ElevationOfPrivilege,
        ThreatSeverity::Critical,
        "kernel",
        vec!["CWE-119".into()],
        vec![],
    ).unwrap();
    svc.register_threat(critical_threat).unwrap();

    let report_new = svc.assess_risk();
    assert_eq!(report_new.total_threats, 8);
    assert_eq!(report_new.identified_count, 1);
    assert_eq!(report_new.critical_unmitigated_count, 1);
    assert_eq!(report_new.overall_risk_score, 10);
}

#[test]
fn test_threat_service_path_validation_and_persistence() {
    // Path validation
    assert!(ThreatModelService::validate_path(std::path::Path::new("safe/threats.json")).is_ok());
    assert!(ThreatModelService::validate_path(std::path::Path::new("../threats.json")).is_err());
    assert!(ThreatModelService::validate_path(std::path::Path::new("\\\\unc\\share\\threats.json")).is_err());

    // Persistence roundtrip
    let tmp_dir = std::env::temp_dir().join("test_threat_svc_persist");
    let _ = fs::create_dir_all(&tmp_dir);
    let store_path = tmp_dir.join("threats.json");

    let svc = ThreatModelService::with_canonical_threats();
    assert!(svc.save_to_path(&store_path).is_ok());
    assert!(store_path.exists());

    let loaded = ThreatModelService::load_from_path(&store_path).expect("load success");
    assert_eq!(loaded.list_threats().len(), 7);

    let _ = fs::remove_dir_all(&tmp_dir);
}
