//! Unit Tests for Compliance Mapping Core Service (T-02815).

use tempfile::tempdir;

use aiosh_core::compliance_data_model::*;
use aiosh_core::compliance_service::*;

#[test]
fn test_compliance_service_save_and_load() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().join("compliance_map.json");

    let svc = ComplianceService::with_canonical_baseline();
    svc.save_to_path(&store_path).expect("save to path");
    assert!(store_path.exists());

    let loaded = ComplianceService::load_from_path(&store_path).expect("load from path");
    assert_eq!(loaded.snapshot.mappings.len(), svc.snapshot.mappings.len());
    assert_eq!(loaded.snapshot.version, svc.snapshot.version);
}

#[test]
fn test_compliance_service_path_traversal_rejection() {
    let dir = tempdir().unwrap();
    let malicious = dir.path().join("../etc/passwd.json");

    let res = ComplianceService::validate_path(&malicious);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains(COMPLIANCESVC_ERR_PATH_TRAVERSAL));

    // Non-json extension
    let bad_ext = dir.path().join("compliance.yaml");
    let res_ext = ComplianceService::validate_path(&bad_ext);
    assert!(res_ext.is_err());
    assert!(res_ext.unwrap_err().contains(COMPLIANCESVC_ERR_PATH_TRAVERSAL));
}

#[test]
fn test_compliance_service_registration_and_update() {
    let mut svc = ComplianceService::new();
    let entry = ComplianceMappingEntry::new(
        "MAP-NIST-AC2",
        "AC-2",
        ComplianceFramework::NistSp80053Rev5,
        SubstrateTargetType::PepGate,
        "account_mgmt_gate",
        vec!["T-SPOOF-001".to_string()],
        ComplianceStatus::NonCompliant,
        "Pending automated verification",
        vec!["identity".to_string()],
    ).unwrap();

    svc.register_mapping(entry.clone()).unwrap();
    assert_eq!(svc.snapshot.mappings.len(), 1);

    // Duplicate registration should fail
    let err_dup = svc.register_mapping(entry);
    assert!(err_dup.is_err());

    // Update status
    svc.update_status("MAP-NIST-AC2", ComplianceStatus::Compliant, "Automated verification active").unwrap();
    let updated = svc.get_mapping("MAP-NIST-AC2").unwrap();
    assert_eq!(updated.status, ComplianceStatus::Compliant);

    // Unknown ID update should fail
    let err_unknown = svc.update_status("UNKNOWN-ID", ComplianceStatus::Compliant, "Reason");
    assert!(err_unknown.is_err());
    assert!(err_unknown.unwrap_err().contains(COMPLIANCESVC_ERR_NOT_FOUND));
}

#[test]
fn test_compliance_service_assessment_reporting() {
    let mut svc = ComplianceService::new();
    let e1 = ComplianceMappingEntry::new(
        "MAP-1",
        "AC-1",
        ComplianceFramework::NistSp80053Rev5,
        SubstrateTargetType::PepGate,
        "gate_1",
        vec![],
        ComplianceStatus::Compliant,
        "Mitigated",
        vec![],
    ).unwrap();
    let e2 = ComplianceMappingEntry::new(
        "MAP-2",
        "AC-2",
        ComplianceFramework::NistSp80053Rev5,
        SubstrateTargetType::PepGate,
        "gate_2",
        vec![],
        ComplianceStatus::NonCompliant,
        "Missing implementation",
        vec![],
    ).unwrap();

    svc.register_mapping(e1).unwrap();
    svc.register_mapping(e2).unwrap();

    let report = svc.assess_framework(Some(ComplianceFramework::NistSp80053Rev5));
    assert_eq!(report.total_mappings, 2);
    assert_eq!(report.compliant_count, 1);
    assert_eq!(report.non_compliant_count, 1);
    assert_eq!(report.compliance_percentage, 50.0);
    assert_eq!(report.gap_control_ids, vec!["AC-2".to_string()]);
}

#[test]
fn test_compliance_service_pep_coverage() {
    let svc = ComplianceService::with_canonical_baseline();

    // Baseline includes pep_enforce_gate and capability_grant_gate
    assert!(svc.verify_pep_coverage("pep_enforce_gate"));
    assert!(svc.verify_pep_coverage("capability_grant_gate"));
    assert!(!svc.verify_pep_coverage("non_existent_gate"));

    let uncovered = svc.uncovered_pep_gates(&[
        "pep_enforce_gate",
        "missing_network_gate",
        "missing_fs_gate",
    ]);
    assert_eq!(uncovered, vec!["missing_network_gate".to_string(), "missing_fs_gate".to_string()]);
}
