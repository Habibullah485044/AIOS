//! End-to-end integration test suite for Compliance Mapping Security Policy (T-02928).
//!
//! Verifies integration between ComplianceService and ComplianceSecurityPolicy,
//! asserting cross-cutting enforcement across registration, lifecycle transitions,
//! capacity constraints, and framework posture assessment.

use aiosh_core::{
    ComplianceFramework, ComplianceMappingEntry,
    CompliancePolicyVerdict, ComplianceSecurityPolicy, ComplianceService,
    ComplianceStatus, SubstrateTargetType,
    COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED, COMPLIANCEPOL_ERR_MITIGATION_REQUIRED,
    COMPLIANCEPOL_ERR_THREAT_REQUIRED, COMPLIANCEPOL_ERR_THRESHOLD_UNMET,
};
use tempfile::tempdir;

#[test]
fn test_compliance_policy_service_integration() {
    let mut service = ComplianceService::with_canonical_baseline();
    let mut policy = ComplianceSecurityPolicy::default();
    policy.permitted_frameworks = vec![
        ComplianceFramework::NistSp80053Rev5,
        ComplianceFramework::Soc2Type2,
        ComplianceFramework::CisControlsV8,
    ];
    service.set_policy(policy);

    // 1. Verify Registration Policy Gating
    // Prohibited framework rejection
    let hipaa_entry = ComplianceMappingEntry {
        id: "map-hipaa-01".into(),
        control_id: "164.312".into(),
        framework: ComplianceFramework::HipaaSecurity,
        target_type: SubstrateTargetType::PepGate,
        target_ref: "pep:gate:hipaa".into(),
        threat_ids: vec!["T-HIPAA-1".into()],
        status: ComplianceStatus::NonCompliant,
        mitigation_summary: "".into(),
        tags: vec!["hipaa".into()],
        created_at: "2026-10-11T00:00:00Z".into(),
        updated_at: "2026-10-11T00:00:00Z".into(),
    };
    let reg_err = service.register_mapping(hipaa_entry).unwrap_err();
    assert!(reg_err.contains(COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED));

    // Missing threat rejection
    let no_threat_entry = ComplianceMappingEntry {
        id: "map-nist-no-threat".into(),
        control_id: "AC-2".into(),
        framework: ComplianceFramework::NistSp80053Rev5,
        target_type: SubstrateTargetType::PepGate,
        target_ref: "pep:gate:ac2".into(),
        threat_ids: vec![],
        status: ComplianceStatus::NonCompliant,
        mitigation_summary: "".into(),
        tags: vec!["nist".into()],
        created_at: "2026-10-11T00:00:00Z".into(),
        updated_at: "2026-10-11T00:00:00Z".into(),
    };
    let threat_err = service.register_mapping(no_threat_entry).unwrap_err();
    assert!(threat_err.contains(COMPLIANCEPOL_ERR_THREAT_REQUIRED));

    // Valid registration
    let valid_entry = ComplianceMappingEntry {
        id: "map-nist-valid".into(),
        control_id: "AC-2".into(),
        framework: ComplianceFramework::NistSp80053Rev5,
        target_type: SubstrateTargetType::PepGate,
        target_ref: "pep:gate:ac2".into(),
        threat_ids: vec!["T-EOP-001".into()],
        status: ComplianceStatus::NonCompliant,
        mitigation_summary: "".into(),
        tags: vec!["nist".into()],
        created_at: "2026-10-11T00:00:00Z".into(),
        updated_at: "2026-10-11T00:00:00Z".into(),
    };
    assert!(service.register_mapping(valid_entry).is_ok());

    // 2. Verify Status Transition Gating
    // Transition to Compliant with empty reason fails policy
    let trans_err = service.update_status("map-nist-valid", ComplianceStatus::Compliant, "").unwrap_err();
    assert!(trans_err.contains(COMPLIANCEPOL_ERR_MITIGATION_REQUIRED));

    // Transition to Compliant with valid mitigation passes
    assert!(service.update_status("map-nist-valid", ComplianceStatus::Compliant, "Cryptographic PEP token redeemed and verified").is_ok());

    // 3. Verify Assessment Posture Evaluation Under Policy
    let (report, verdict) = service.assess_framework_with_policy(Some(ComplianceFramework::NistSp80053Rev5));
    assert_eq!(verdict, CompliancePolicyVerdict::Permit);
    assert_eq!(report.compliant_count, 3);

    // Increase min_compliant_percentage to 100% and test failure when partial
    service.policy_mut().unwrap().min_compliant_percentage = 100.0;
    // Add a non-compliant entry
    let pending_entry = ComplianceMappingEntry {
        id: "map-nist-pending".into(),
        control_id: "AC-3".into(),
        framework: ComplianceFramework::NistSp80053Rev5,
        target_type: SubstrateTargetType::PepGate,
        target_ref: "pep:gate:ac3".into(),
        threat_ids: vec!["T-EOP-001".into()],
        status: ComplianceStatus::NonCompliant,
        mitigation_summary: "".into(),
        tags: vec!["nist".into()],
        created_at: "2026-10-11T00:00:00Z".into(),
        updated_at: "2026-10-11T00:00:00Z".into(),
    };
    assert!(service.register_mapping(pending_entry).is_ok());

    let (strict_rep, strict_verdict) = service.assess_framework_with_policy(Some(ComplianceFramework::NistSp80053Rev5));
    assert!(strict_verdict.is_denied());
    match strict_verdict {
        CompliancePolicyVerdict::Deny { code, .. } => assert_eq!(code, COMPLIANCEPOL_ERR_THRESHOLD_UNMET),
        _ => panic!("Expected Deny on unmet threshold"),
    }
    assert!(strict_rep.compliance_percentage < 100.0);

    // 4. Persistence Roundtrip with Active Policy
    let dir = tempdir().unwrap();
    let store_path = dir.path().join("compliance_map.json");
    service.save_to_path(&store_path).unwrap();

    let reloaded = ComplianceService::load_from_path(&store_path).unwrap();
    assert_eq!(reloaded.snapshot.mappings.len(), service.snapshot.mappings.len());
}
