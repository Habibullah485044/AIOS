//! Unit Tests for Threat Model Observability (T-02775).

use aiosh_core::threat_model_data_model::{ThreatCategory, ThreatEntry, ThreatSeverity, ThreatStatus};
use aiosh_core::threat_model_policy::{ThreatModelSecurityPolicy, ThreatPolicyMode};
use aiosh_core::threat_model_service::ThreatModelService;
use aiosh_core::threat_model_observability::{
    sanitize_telemetry_text, ThreatModelObservabilityReport,
    MAX_TELEMETRY_TEXT_LEN, THREATOBS_ERR_VALIDATION,
};

fn make_test_threat(id: &str, category: ThreatCategory, severity: ThreatSeverity, cwe: &str) -> ThreatEntry {
    ThreatEntry::new(
        id,
        &format!("Title {}", id),
        "Test threat vector description",
        category,
        severity,
        "kernel.test.component",
        vec![cwe.to_string()],
        vec![],
    )
    .expect("valid entry")
}

#[test]
fn test_observability_empty_catalog() {
    let service = ThreatModelService::new();
    let report = ThreatModelObservabilityReport::generate(&service, None).expect("report succeeds");

    assert_eq!(report.total_threats, 0);
    assert_eq!(report.threats_by_category.len(), 0);
    assert_eq!(report.threats_by_severity.len(), 0);
    assert_eq!(report.threats_by_status.len(), 0);
    assert_eq!(report.critical_unmitigated_count, 0);
    assert_eq!(report.overall_risk_score, 0);
    assert_eq!(report.policy_mode, "unconfigured");
    assert!(report.is_healthy);
    assert_eq!(report.recent_audit_events_count, 0);
    assert!(report.validate().is_ok());
}

#[test]
fn test_observability_populated_catalog() {
    let mut service = ThreatModelService::new();
    let t1 = make_test_threat("THREAT-01", ThreatCategory::Spoofing, ThreatSeverity::High, "CWE-287");
    let t2 = make_test_threat("THREAT-02", ThreatCategory::Tampering, ThreatSeverity::Critical, "CWE-284");
    let mut t3 = make_test_threat("THREAT-03", ThreatCategory::ElevationOfPrivilege, ThreatSeverity::Low, "CWE-269");
    t3.transition_to(ThreatStatus::UnderReview).unwrap();

    service.register_threat(t1).unwrap();
    service.register_threat(t2).unwrap();
    service.register_threat(t3).unwrap();

    let report = service.observability_report(None).expect("report succeeds");

    assert_eq!(report.total_threats, 3);
    assert_eq!(report.threats_by_category.get("spoofing"), Some(&1));
    assert_eq!(report.threats_by_category.get("tampering"), Some(&1));
    assert_eq!(report.threats_by_category.get("elevation_of_privilege"), Some(&1));

    assert_eq!(report.threats_by_severity.get("high"), Some(&1));
    assert_eq!(report.threats_by_severity.get("critical"), Some(&1));
    assert_eq!(report.threats_by_severity.get("low"), Some(&1));

    assert_eq!(report.threats_by_status.get("identified"), Some(&2));
    assert_eq!(report.threats_by_status.get("under_review"), Some(&1));

    assert_eq!(report.critical_unmitigated_count, 1);
    assert!(report.overall_risk_score > 0);
    assert!(report.is_healthy);
}

#[test]
fn test_observability_canonical_threats() {
    let service = ThreatModelService::with_canonical_threats();
    let report = service.observability_report(None).expect("report succeeds");

    assert_eq!(report.total_threats, 7);
    assert_eq!(report.threats_by_category.len(), 7);
    assert!(report.threats_by_category.contains_key("spoofing"));
    assert!(report.threats_by_category.contains_key("tampering"));
    assert!(report.threats_by_category.contains_key("repudiation"));
    assert!(report.threats_by_category.contains_key("information_disclosure"));
    assert!(report.threats_by_category.contains_key("denial_of_service"));
    assert!(report.threats_by_category.contains_key("elevation_of_privilege"));
    assert!(report.threats_by_category.contains_key("supply_chain_risk"));

    assert!(report.is_healthy);
    assert!(report.validate().is_ok());
}

#[test]
fn test_observability_sanitize_text() {
    let input_with_control = "stride\x00\x1fthreat\n\r\t";
    let cleaned = sanitize_telemetry_text(input_with_control);
    assert_eq!(cleaned, "stridethreat");

    let long_input = "x".repeat(600);
    let truncated = sanitize_telemetry_text(&long_input);
    assert_eq!(truncated.len(), MAX_TELEMETRY_TEXT_LEN);
}

#[test]
fn test_observability_policy_mode_reflection() {
    let mut service = ThreatModelService::new();

    let mut policy = ThreatModelSecurityPolicy::default();
    policy.mode = ThreatPolicyMode::Enforcing;
    service.set_policy(policy);

    let report1 = service.observability_report(None).unwrap();
    assert_eq!(report1.policy_mode, "enforcing");

    service.policy_mut().unwrap().mode = ThreatPolicyMode::Permissive;
    let report2 = service.observability_report(None).unwrap();
    assert_eq!(report2.policy_mode, "permissive");

    service.policy_mut().unwrap().mode = ThreatPolicyMode::Disabled;
    let report3 = service.observability_report(None).unwrap();
    assert_eq!(report3.policy_mode, "disabled");
}

#[test]
fn test_observability_validation_rejections() {
    let service = ThreatModelService::new();
    let mut report = service.observability_report(None).unwrap();

    // 1. Empty timestamp rejected
    report.generated_at_utc = "   ".to_string();
    let err1 = report.validate().unwrap_err();
    assert!(err1.contains(THREATOBS_ERR_VALIDATION));

    // 2. Invalid RFC3339 timestamp rejected
    report.generated_at_utc = "2026-13-99 99:99:99".to_string();
    let err2 = report.validate().unwrap_err();
    assert!(err2.contains(THREATOBS_ERR_VALIDATION));

    // 3. Control character in label rejected
    report.generated_at_utc = chrono::Utc::now().to_rfc3339();
    report.threats_by_category.insert("bad\x07category".to_string(), 1);
    let err3 = report.validate().unwrap_err();
    assert!(err3.contains(THREATOBS_ERR_VALIDATION));

    // 4. Oversized label rejected
    report.threats_by_category.clear();
    report.threats_by_category.insert("o".repeat(300), 1);
    let err4 = report.validate().unwrap_err();
    assert!(err4.contains(THREATOBS_ERR_VALIDATION));
}

#[test]
fn test_observability_json_roundtrip() {
    let service = ThreatModelService::with_canonical_threats();
    let report = service.observability_report(None).unwrap();

    let json_str = report.to_json().expect("to_json succeeds");
    let roundtrip = ThreatModelObservabilityReport::from_json(&json_str).expect("from_json succeeds");
    assert_eq!(report, roundtrip);

    // Broken JSON parsing fails
    let err = ThreatModelObservabilityReport::from_json("{ corrupt }").unwrap_err();
    assert!(err.contains(THREATOBS_ERR_VALIDATION));
}
