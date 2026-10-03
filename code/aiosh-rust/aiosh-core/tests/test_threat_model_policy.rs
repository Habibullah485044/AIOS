//! Unit Tests for Threat Model Security Policy (T-02765).

use std::fs;
use tempfile::tempdir;

use aiosh_core::threat_model_data_model::{ThreatCategory, ThreatEntry, ThreatSeverity, ThreatStatus};
use aiosh_core::threat_model_service::ThreatRiskAssessment;
use aiosh_core::threat_model_policy::{
    ThreatModelSecurityPolicy, ThreatPolicyMode, ThreatPolicyVerdict,
    MAX_THREAT_SECURITY_POLICY_BYTES,
    THREATPOL_ERR_CAPACITY_EXCEEDED, THREATPOL_ERR_CATEGORY_PROHIBITED,
    THREATPOL_ERR_CWE_REQUIRED, THREATPOL_ERR_CRITICAL_UNMITIGATED,
    THREATPOL_ERR_DENIED, THREATPOL_ERR_PARSE, THREATPOL_ERR_VALIDATION,
};

fn make_test_threat(id: &str, category: ThreatCategory, severity: ThreatSeverity, cwes: Vec<&str>) -> ThreatEntry {
    ThreatEntry::new(
        id,
        &format!("Title {}", id),
        "Test threat vector details",
        category,
        severity,
        "kernel.threat.asset",
        cwes.into_iter().map(String::from).collect(),
        vec![],
    )
    .expect("valid entry")
}

#[test]
fn test_threat_policy_defaults_and_validation() {
    let policy = ThreatModelSecurityPolicy::default();
    assert_eq!(policy.mode, ThreatPolicyMode::Enforcing);
    assert_eq!(policy.version, "1.0.0");
    assert!(policy.require_cwe_mapping);
    assert!(policy.disallow_unmitigated_critical);
    assert_eq!(policy.max_catalog_threats, 512);
    assert_eq!(policy.max_critical_threats, 16);
    assert!(!policy.allow_canonical_override);
    assert!(policy.validate().is_ok());

    // Invalid version: empty
    let mut bad_ver = policy.clone();
    bad_ver.version = "   ".into();
    assert!(bad_ver.validate().is_err());

    // Invalid version: not starting with 1.
    let mut bad_ver2 = policy.clone();
    bad_ver2.version = "2.0.0".into();
    assert!(bad_ver2.validate().is_err());

    // Invalid max_catalog_threats: 0
    let mut bad_max = policy.clone();
    bad_max.max_catalog_threats = 0;
    assert!(bad_max.validate().is_err());

    // Invalid max_catalog_threats: > 4096
    let mut bad_max2 = policy.clone();
    bad_max2.max_catalog_threats = 5000;
    assert!(bad_max2.validate().is_err());

    // Invalid critical > catalog
    let mut bad_crit = policy.clone();
    bad_crit.max_critical_threats = 1000;
    bad_crit.max_catalog_threats = 500;
    assert!(bad_crit.validate().is_err());
}

#[test]
fn test_threat_policy_evaluate_registration() {
    let mut policy = ThreatModelSecurityPolicy::default();
    policy.prohibited_categories = vec![ThreatCategory::Repudiation];

    let entry_valid = make_test_threat("THREAT-01", ThreatCategory::Tampering, ThreatSeverity::High, vec!["CWE-284"]);
    assert_eq!(policy.evaluate_registration(&entry_valid), ThreatPolicyVerdict::Permit);

    // Prohibited category in Enforcing mode
    let entry_prohibited = make_test_threat("THREAT-02", ThreatCategory::Repudiation, ThreatSeverity::Medium, vec!["CWE-284"]);
    match policy.evaluate_registration(&entry_prohibited) {
        ThreatPolicyVerdict::Deny { code, .. } => assert_eq!(code, THREATPOL_ERR_CATEGORY_PROHIBITED),
        other => panic!("expected Deny, got {:?}", other),
    }

    // Prohibited category in Permissive mode
    policy.mode = ThreatPolicyMode::Permissive;
    match policy.evaluate_registration(&entry_prohibited) {
        ThreatPolicyVerdict::PermitWithWarning { .. } => (),
        other => panic!("expected PermitWithWarning, got {:?}", other),
    }

    // Prohibited category in Disabled mode
    policy.mode = ThreatPolicyMode::Disabled;
    assert_eq!(policy.evaluate_registration(&entry_prohibited), ThreatPolicyVerdict::Permit);

    // Missing CWE requirement in Enforcing mode
    policy.mode = ThreatPolicyMode::Enforcing;
    let entry_no_cwe = make_test_threat("THREAT-03", ThreatCategory::Tampering, ThreatSeverity::High, vec![]);
    match policy.evaluate_registration(&entry_no_cwe) {
        ThreatPolicyVerdict::Deny { code, .. } => assert_eq!(code, THREATPOL_ERR_CWE_REQUIRED),
        other => panic!("expected Deny, got {:?}", other),
    }

    // Missing CWE in Permissive mode
    policy.mode = ThreatPolicyMode::Permissive;
    match policy.evaluate_registration(&entry_no_cwe) {
        ThreatPolicyVerdict::PermitWithWarning { .. } => (),
        other => panic!("expected PermitWithWarning, got {:?}", other),
    }
}

#[test]
fn test_threat_policy_evaluate_transition() {
    let mut policy = ThreatModelSecurityPolicy::default();
    let mut critical_threat = make_test_threat("THREAT-CRIT-01", ThreatCategory::ElevationOfPrivilege, ThreatSeverity::Critical, vec!["CWE-269"]);

    // Transition to UnderReview without mitigations: Permitted
    assert_eq!(policy.evaluate_transition(&critical_threat, ThreatStatus::UnderReview), ThreatPolicyVerdict::Permit);

    // Transition to Accepted without mitigations: Denied in Enforcing
    match policy.evaluate_transition(&critical_threat, ThreatStatus::Accepted) {
        ThreatPolicyVerdict::Deny { code, .. } => assert_eq!(code, THREATPOL_ERR_CRITICAL_UNMITIGATED),
        other => panic!("expected Deny, got {:?}", other),
    }

    // Transition to Resolved without mitigations: Denied in Enforcing
    match policy.evaluate_transition(&critical_threat, ThreatStatus::Resolved) {
        ThreatPolicyVerdict::Deny { code, .. } => assert_eq!(code, THREATPOL_ERR_CRITICAL_UNMITIGATED),
        other => panic!("expected Deny, got {:?}", other),
    }

    // Permissive mode emits warning
    policy.mode = ThreatPolicyMode::Permissive;
    match policy.evaluate_transition(&critical_threat, ThreatStatus::Resolved) {
        ThreatPolicyVerdict::PermitWithWarning { .. } => (),
        other => panic!("expected PermitWithWarning, got {:?}", other),
    }

    // Disabled mode permits
    policy.mode = ThreatPolicyMode::Disabled;
    assert_eq!(policy.evaluate_transition(&critical_threat, ThreatStatus::Resolved), ThreatPolicyVerdict::Permit);

    // Enforcing with mitigation added: Permitted
    policy.mode = ThreatPolicyMode::Enforcing;
    critical_threat.add_mitigation("Enforce mTLS and strict ACL").unwrap();
    assert_eq!(policy.evaluate_transition(&critical_threat, ThreatStatus::Resolved), ThreatPolicyVerdict::Permit);
    assert_eq!(policy.evaluate_transition(&critical_threat, ThreatStatus::Accepted), ThreatPolicyVerdict::Permit);

    // Low severity threat without mitigations: Permitted
    let low_threat = make_test_threat("THREAT-LOW-01", ThreatCategory::InformationDisclosure, ThreatSeverity::Low, vec!["CWE-200"]);
    assert_eq!(policy.evaluate_transition(&low_threat, ThreatStatus::Resolved), ThreatPolicyVerdict::Permit);
}

#[test]
fn test_threat_policy_evaluate_mitigation() {
    let mut policy = ThreatModelSecurityPolicy::default();
    let entry = make_test_threat("THREAT-01", ThreatCategory::Tampering, ThreatSeverity::High, vec!["CWE-284"]);

    // Valid mitigation
    assert_eq!(policy.evaluate_mitigation(&entry, "Cryptographic signature verification"), ThreatPolicyVerdict::Permit);

    // Empty mitigation: Denied
    match policy.evaluate_mitigation(&entry, "   ") {
        ThreatPolicyVerdict::Deny { code, .. } => assert_eq!(code, THREATPOL_ERR_DENIED),
        other => panic!("expected Deny, got {:?}", other),
    }

    // Permissive mode
    policy.mode = ThreatPolicyMode::Permissive;
    match policy.evaluate_mitigation(&entry, "   ") {
        ThreatPolicyVerdict::PermitWithWarning { .. } => (),
        other => panic!("expected PermitWithWarning, got {:?}", other),
    }

    // Disabled mode
    policy.mode = ThreatPolicyMode::Disabled;
    assert_eq!(policy.evaluate_mitigation(&entry, "   "), ThreatPolicyVerdict::Permit);
}

#[test]
fn test_threat_policy_evaluate_assessment() {
    let mut policy = ThreatModelSecurityPolicy::default();
    policy.max_catalog_threats = 10;
    policy.max_critical_threats = 2;

    let normal_assessment = ThreatRiskAssessment {
        total_threats: 8,
        identified_count: 5,
        under_review_count: 1,
        mitigated_count: 1,
        accepted_count: 1,
        resolved_count: 0,
        critical_unmitigated_count: 1,
        overall_risk_score: 55,
        evaluated_at: "2026-10-03T00:00:00Z".to_string(),
    };
    assert_eq!(policy.evaluate_assessment(&normal_assessment), ThreatPolicyVerdict::Permit);

    // Exceed total threats limit
    let overflow_assessment = ThreatRiskAssessment {
        total_threats: 15,
        identified_count: 10,
        under_review_count: 2,
        mitigated_count: 2,
        accepted_count: 1,
        resolved_count: 0,
        critical_unmitigated_count: 1,
        overall_risk_score: 110,
        evaluated_at: "2026-10-03T00:00:00Z".to_string(),
    };
    match policy.evaluate_assessment(&overflow_assessment) {
        ThreatPolicyVerdict::Deny { code, .. } => assert_eq!(code, THREATPOL_ERR_CAPACITY_EXCEEDED),
        other => panic!("expected Deny, got {:?}", other),
    }

    // Exceed critical unmitigated limit
    let critical_overflow_assessment = ThreatRiskAssessment {
        total_threats: 8,
        identified_count: 5,
        under_review_count: 1,
        mitigated_count: 0,
        accepted_count: 1,
        resolved_count: 1,
        critical_unmitigated_count: 5,
        overall_risk_score: 200,
        evaluated_at: "2026-10-03T00:00:00Z".to_string(),
    };
    match policy.evaluate_assessment(&critical_overflow_assessment) {
        ThreatPolicyVerdict::Deny { code, .. } => assert_eq!(code, THREATPOL_ERR_CAPACITY_EXCEEDED),
        other => panic!("expected Deny, got {:?}", other),
    }

    // Permissive mode
    policy.mode = ThreatPolicyMode::Permissive;
    match policy.evaluate_assessment(&critical_overflow_assessment) {
        ThreatPolicyVerdict::PermitWithWarning { .. } => (),
        other => panic!("expected PermitWithWarning, got {:?}", other),
    }
}

#[test]
fn test_threat_policy_persistence_and_atomic_save() {
    let tmp = tempdir().expect("tempdir");
    let file_path = tmp.path().join("threat_policy.json");

    let policy = ThreatModelSecurityPolicy {
        version: "1.0.0".into(),
        mode: ThreatPolicyMode::Permissive,
        require_cwe_mapping: false,
        disallow_unmitigated_critical: true,
        prohibited_categories: vec![ThreatCategory::InformationDisclosure],
        max_catalog_threats: 256,
        max_critical_threats: 8,
        allow_canonical_override: true,
    };

    // Save and reload
    policy.save_to_path(&file_path).expect("save succeeded");
    let loaded = ThreatModelSecurityPolicy::load_from_path(&file_path).expect("load succeeded");
    assert_eq!(policy, loaded);

    // Malformed JSON fails with parse error
    fs::write(&file_path, "{ broken json }").expect("write broken");
    let err = ThreatModelSecurityPolicy::load_from_path(&file_path).unwrap_err();
    assert!(err.contains(THREATPOL_ERR_PARSE));

    // File exceeding MAX_THREAT_SECURITY_POLICY_BYTES
    let large_data = format!("{{\"version\": \"{}\"}}", "A".repeat((MAX_THREAT_SECURITY_POLICY_BYTES + 10) as usize));
    fs::write(&file_path, large_data).expect("write large");
    let err = ThreatModelSecurityPolicy::load_from_path(&file_path).unwrap_err();
    assert!(err.contains(THREATPOL_ERR_VALIDATION));
}

#[test]
fn test_threat_policy_hardening_and_resilience() {
    let tmp = tempdir().expect("tempdir");
    let base_dir = tmp.path();

    // 1. Non-existent path handling
    let missing_path = base_dir.join("non_existent_policy.json");
    let err_missing = ThreatModelSecurityPolicy::load_from_path(&missing_path).unwrap_err();
    assert!(err_missing.contains(aiosh_core::threat_model_policy::THREATPOL_ERR_IO));

    // 2. Zero tempfile leakage on save
    let save_target = base_dir.join("subdir/nested/hardened_policy.json");
    let policy = ThreatModelSecurityPolicy::default();
    policy.save_to_path(&save_target).expect("nested save should succeed");

    let entries = fs::read_dir(save_target.parent().unwrap()).expect("read_dir");
    let tmp_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
        .collect();
    assert!(tmp_files.is_empty(), "Found leaked temporary files: {:?}", tmp_files);

    // 3. Rejection of unmitigated critical transition with empty space mitigation
    let mut entry = make_test_threat("THREAT-HARDEN-01", ThreatCategory::Spoofing, ThreatSeverity::Critical, vec!["CWE-287"]);
    let verdict = policy.evaluate_mitigation(&entry, "   \t\n   ");
    match verdict {
        ThreatPolicyVerdict::Deny { code, .. } => assert_eq!(code, THREATPOL_ERR_DENIED),
        other => panic!("expected Deny, got {:?}", other),
    }

    // 4. Invariant that critical unmitigated transition cannot bypass even if status was already UnderReview
    entry.status = ThreatStatus::UnderReview;
    let verdict_trans = policy.evaluate_transition(&entry, ThreatStatus::Accepted);
    match verdict_trans {
        ThreatPolicyVerdict::Deny { code, .. } => assert_eq!(code, THREATPOL_ERR_CRITICAL_UNMITIGATED),
        other => panic!("expected Deny, got {:?}", other),
    }
}

