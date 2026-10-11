//! Standalone unit test suite for Compliance Mapping Security Policy (T-02927).
//!
//! Asserts COMPLIANCEPOL1..COMPLIANCEPOL7 invariants, evaluation verdicts,
//! boundary conditions, and file persistence across happy and negative paths.

use aiosh_core::{
    ComplianceAssessmentReport, ComplianceFramework, ComplianceMappingEntry,
    CompliancePolicyMode, CompliancePolicyVerdict, ComplianceSecurityPolicy,
    ComplianceStatus, SubstrateTargetType,
    COMPLIANCEPOL_ERR_CAPACITY_EXCEEDED, COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED,
    COMPLIANCEPOL_ERR_MITIGATION_REQUIRED, COMPLIANCEPOL_ERR_OVERRIDE_FORBIDDEN,
    COMPLIANCEPOL_ERR_THREAT_REQUIRED, COMPLIANCEPOL_ERR_THRESHOLD_UNMET,
    COMPLIANCEPOL_ERR_VALIDATION,
};
use tempfile::tempdir;

fn sample_entry(
    status: ComplianceStatus,
    mitigation: &str,
    threats: Vec<&str>,
    framework: ComplianceFramework,
) -> ComplianceMappingEntry {
    ComplianceMappingEntry {
        id: "map-unit-01".into(),
        control_id: "AC-1".into(),
        framework,
        target_type: SubstrateTargetType::PepGate,
        target_ref: "pep:gate:access".into(),
        threat_ids: threats.into_iter().map(String::from).collect(),
        status,
        mitigation_summary: mitigation.into(),
        tags: vec!["unit_test".into()],
        created_at: "2026-10-11T00:00:00Z".into(),
        updated_at: "2026-10-11T00:00:00Z".into(),
    }
}

#[test]
fn test_default_policy_validation() {
    let policy = ComplianceSecurityPolicy::default();
    assert!(policy.validate().is_ok());
    assert_eq!(policy.version, "1.0.0");
    assert_eq!(policy.mode, CompliancePolicyMode::Enforcing);
    assert_eq!(policy.min_compliant_percentage, 80.0);
    assert_eq!(policy.max_catalog_mappings, 1024);
}

#[test]
fn test_version_validation_negative() {
    let mut policy = ComplianceSecurityPolicy::default();
    policy.version = "".into();
    let err = policy.validate().unwrap_err();
    assert!(err.contains(COMPLIANCEPOL_ERR_VALIDATION));

    policy.version = "2.0.0".into();
    let err2 = policy.validate().unwrap_err();
    assert!(err2.contains(COMPLIANCEPOL_ERR_VALIDATION));
}

#[test]
fn test_bounds_validation_negative() {
    let mut p_zero = ComplianceSecurityPolicy::default();
    p_zero.max_catalog_mappings = 0;
    assert!(p_zero.validate().unwrap_err().contains(COMPLIANCEPOL_ERR_VALIDATION));

    let mut p_over = ComplianceSecurityPolicy::default();
    p_over.max_catalog_mappings = 5000;
    assert!(p_over.validate().unwrap_err().contains(COMPLIANCEPOL_ERR_VALIDATION));

    let mut p_pct_neg = ComplianceSecurityPolicy::default();
    p_pct_neg.min_compliant_percentage = -1.0;
    assert!(p_pct_neg.validate().unwrap_err().contains(COMPLIANCEPOL_ERR_VALIDATION));

    let mut p_pct_over = ComplianceSecurityPolicy::default();
    p_pct_over.min_compliant_percentage = 101.0;
    assert!(p_pct_over.validate().unwrap_err().contains(COMPLIANCEPOL_ERR_VALIDATION));
}

#[test]
fn test_registration_evaluation_happy_path() {
    let policy = ComplianceSecurityPolicy::default();
    let entry = sample_entry(
        ComplianceStatus::Compliant,
        "PEP gate enforced and verified",
        vec!["THREAT-1"],
        ComplianceFramework::NistSp80053Rev5,
    );
    assert_eq!(policy.evaluate_registration(&entry), CompliancePolicyVerdict::Permit);
    assert!(policy.evaluate_registration(&entry).is_permitted());
}

#[test]
fn test_registration_missing_threat_ids() {
    let policy = ComplianceSecurityPolicy::default();
    let entry = sample_entry(
        ComplianceStatus::NonCompliant,
        "",
        vec![],
        ComplianceFramework::NistSp80053Rev5,
    );
    let verdict = policy.evaluate_registration(&entry);
    assert!(verdict.is_denied());
    match verdict {
        CompliancePolicyVerdict::Deny { code, .. } => assert_eq!(code, COMPLIANCEPOL_ERR_THREAT_REQUIRED),
        _ => panic!("Expected Deny"),
    }
}

#[test]
fn test_registration_compliant_without_mitigation() {
    let policy = ComplianceSecurityPolicy::default();
    let entry = sample_entry(
        ComplianceStatus::Compliant,
        "",
        vec!["THREAT-1"],
        ComplianceFramework::NistSp80053Rev5,
    );
    let verdict = policy.evaluate_registration(&entry);
    assert!(verdict.is_denied());
    match verdict {
        CompliancePolicyVerdict::Deny { code, .. } => assert_eq!(code, COMPLIANCEPOL_ERR_MITIGATION_REQUIRED),
        _ => panic!("Expected Deny"),
    }
}

#[test]
fn test_registration_framework_whitelist() {
    let mut policy = ComplianceSecurityPolicy::default();
    policy.permitted_frameworks = vec![ComplianceFramework::Soc2Type2];

    let entry_nist = sample_entry(
        ComplianceStatus::NonCompliant,
        "",
        vec!["THREAT-1"],
        ComplianceFramework::NistSp80053Rev5,
    );
    let verdict = policy.evaluate_registration(&entry_nist);
    assert!(verdict.is_denied());
    match verdict {
        CompliancePolicyVerdict::Deny { code, .. } => assert_eq!(code, COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED),
        _ => panic!("Expected Deny"),
    }

    let entry_soc2 = sample_entry(
        ComplianceStatus::NonCompliant,
        "",
        vec!["THREAT-1"],
        ComplianceFramework::Soc2Type2,
    );
    assert_eq!(policy.evaluate_registration(&entry_soc2), CompliancePolicyVerdict::Permit);
}

#[test]
fn test_permissive_and_disabled_modes() {
    let perm_policy = ComplianceSecurityPolicy::permissive();
    let entry_bad = sample_entry(
        ComplianceStatus::NonCompliant,
        "",
        vec![],
        ComplianceFramework::NistSp80053Rev5,
    );
    let verdict_perm = perm_policy.evaluate_registration(&entry_bad);
    assert!(matches!(verdict_perm, CompliancePolicyVerdict::PermitWithWarning { .. }));
    assert!(verdict_perm.is_permitted());

    let dis_policy = ComplianceSecurityPolicy::disabled();
    let verdict_dis = dis_policy.evaluate_registration(&entry_bad);
    assert_eq!(verdict_dis, CompliancePolicyVerdict::Permit);
}

#[test]
fn test_status_transition_evaluation() {
    let policy = ComplianceSecurityPolicy::default();
    let entry = sample_entry(
        ComplianceStatus::NonCompliant,
        "",
        vec!["THREAT-1"],
        ComplianceFramework::NistSp80053Rev5,
    );

    // Empty mitigation transition -> Deny
    let v_empty = policy.evaluate_status_transition(&entry, ComplianceStatus::Compliant, "");
    assert!(v_empty.is_denied());
    match v_empty {
        CompliancePolicyVerdict::Deny { code, .. } => assert_eq!(code, COMPLIANCEPOL_ERR_MITIGATION_REQUIRED),
        _ => panic!("Expected Deny"),
    }

    // Valid mitigation transition -> Permit
    let v_valid = policy.evaluate_status_transition(&entry, ComplianceStatus::Compliant, "Cryptographic checks pass");
    assert_eq!(v_valid, CompliancePolicyVerdict::Permit);

    // NonCompliant transition -> Permit
    let v_non = policy.evaluate_status_transition(&entry, ComplianceStatus::NonCompliant, "");
    assert_eq!(v_non, CompliancePolicyVerdict::Permit);
}

#[test]
fn test_assessment_evaluation() {
    let policy = ComplianceSecurityPolicy::default();

    let passing_rep = ComplianceAssessmentReport {
        total_mappings: 10,
        compliant_count: 9,
        partially_compliant_count: 0,
        non_compliant_count: 1,
        not_applicable_count: 0,
        compliance_percentage: 90.0,
        gap_control_ids: vec!["AC-2".into()],
        evaluated_at: "2026-10-11T00:00:00Z".into(),
    };
    assert_eq!(policy.evaluate_assessment(&passing_rep), CompliancePolicyVerdict::Permit);

    let failing_rep = ComplianceAssessmentReport {
        total_mappings: 10,
        compliant_count: 6,
        partially_compliant_count: 2,
        non_compliant_count: 2,
        not_applicable_count: 0,
        compliance_percentage: 60.0,
        gap_control_ids: vec!["AC-2".into(), "AC-3".into()],
        evaluated_at: "2026-10-11T00:00:00Z".into(),
    };
    let v_fail = policy.evaluate_assessment(&failing_rep);
    assert!(v_fail.is_denied());
    match v_fail {
        CompliancePolicyVerdict::Deny { code, .. } => assert_eq!(code, COMPLIANCEPOL_ERR_THRESHOLD_UNMET),
        _ => panic!("Expected Deny"),
    }
}

#[test]
fn test_capacity_and_override_evaluation() {
    let mut policy = ComplianceSecurityPolicy::default();
    policy.max_catalog_mappings = 100;

    assert_eq!(policy.evaluate_capacity(50), CompliancePolicyVerdict::Permit);

    let v_cap = policy.evaluate_capacity(100);
    assert!(v_cap.is_denied());
    match v_cap {
        CompliancePolicyVerdict::Deny { code, .. } => assert_eq!(code, COMPLIANCEPOL_ERR_CAPACITY_EXCEEDED),
        _ => panic!("Expected Deny"),
    }

    let v_over = policy.evaluate_override("admin");
    assert!(v_over.is_denied());
    match v_over {
        CompliancePolicyVerdict::Deny { code, .. } => assert_eq!(code, COMPLIANCEPOL_ERR_OVERRIDE_FORBIDDEN),
        _ => panic!("Expected Deny"),
    }

    policy.allow_canonical_override = true;
    assert_eq!(policy.evaluate_override("admin"), CompliancePolicyVerdict::Permit);
}

#[test]
fn test_file_persistence_roundtrip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("compliance_policy.json");

    let mut policy = ComplianceSecurityPolicy::default();
    policy.permitted_frameworks = vec![ComplianceFramework::Soc2Type2, ComplianceFramework::Iso27001];
    policy.min_compliant_percentage = 85.0;

    policy.save_to_path(&path).unwrap();

    let loaded = ComplianceSecurityPolicy::load_from_path(&path).unwrap();
    assert_eq!(loaded.permitted_frameworks, vec![ComplianceFramework::Soc2Type2, ComplianceFramework::Iso27001]);
    assert_eq!(loaded.min_compliant_percentage, 85.0);
    assert_eq!(loaded.mode, CompliancePolicyMode::Enforcing);
}
