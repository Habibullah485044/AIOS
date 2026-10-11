//! Comprehensive Unit Tests for Compliance Mapping Observability (T-02937).

use std::collections::HashMap;
use aiosh_core::audit::{AuditRing, AuditRowInput};
use aiosh_core::compliance_data_model::{
    ComplianceFramework, ComplianceMappingEntry, ComplianceStatus, SubstrateTargetType,
};
use aiosh_core::compliance_observability::{
    sanitize_telemetry_text, ComplianceObservabilityReport, COMPOBS_ERR_VALIDATION,
    MAX_OUTCOME_DISTRIBUTION_ENTRIES, MAX_TELEMETRY_TEXT_LEN,
};
use aiosh_core::compliance_policy::{ComplianceSecurityPolicy, CompliancePolicyMode};
use aiosh_core::compliance_service::ComplianceService;

fn make_test_mapping(id: &str, fw: ComplianceFramework, st: ComplianceStatus, tt: SubstrateTargetType) -> ComplianceMappingEntry {
    ComplianceMappingEntry::new(
        id,
        "AC-1",
        fw,
        tt,
        "kernel.test.component",
        vec!["THREAT-01".to_string()],
        st,
        if st == ComplianceStatus::Compliant { "Documented mitigation summary" } else { "" },
        vec![],
    )
    .expect("valid test entry")
}

#[test]
fn test_empty_catalog_observability() {
    let svc = ComplianceService::new();
    let report = ComplianceObservabilityReport::generate(&svc, None).expect("generate succeeded");

    assert_eq!(report.total_mappings, 0);
    assert_eq!(report.mappings_by_framework.len(), 0);
    assert_eq!(report.mappings_by_status.len(), 0);
    assert_eq!(report.mappings_by_target_type.len(), 0);
    assert_eq!(report.compliance_percentage, 100.0);
    assert_eq!(report.gap_control_count, 0);
    assert_eq!(report.policy_mode, "unconfigured");
    assert_eq!(report.capacity_utilization_percent, 0);
    assert!(report.is_healthy);
    assert_eq!(report.recent_audit_events_count, 0);
    assert!(report.validate().is_ok());
}

#[test]
fn test_populated_catalog_distributions() {
    let mut svc = ComplianceService::new();
    let m1 = make_test_mapping("MAP-01", ComplianceFramework::NistSp80053Rev5, ComplianceStatus::Compliant, SubstrateTargetType::PepGate);
    let m2 = make_test_mapping("MAP-02", ComplianceFramework::Iso27001, ComplianceStatus::NonCompliant, SubstrateTargetType::AuditRing);
    let m3 = make_test_mapping("MAP-03", ComplianceFramework::Soc2Type2, ComplianceStatus::PartiallyCompliant, SubstrateTargetType::PepGate);

    svc.register_mapping(m1).expect("m1 register");
    svc.register_mapping(m2).expect("m2 register");
    svc.register_mapping(m3).expect("m3 register");

    let report = svc.observability_report(None).expect("generate succeeded");
    assert_eq!(report.total_mappings, 3);
    assert_eq!(report.mappings_by_framework.get("nist_sp_800_53_rev5"), Some(&1));
    assert_eq!(report.mappings_by_framework.get("iso_27001_2022"), Some(&1));
    assert_eq!(report.mappings_by_framework.get("soc2_type2"), Some(&1));

    assert_eq!(report.mappings_by_status.get("compliant"), Some(&1));
    assert_eq!(report.mappings_by_status.get("non_compliant"), Some(&1));
    assert_eq!(report.mappings_by_status.get("partially_compliant"), Some(&1));

    assert_eq!(report.mappings_by_target_type.get("pep_gate"), Some(&2));
    assert_eq!(report.mappings_by_target_type.get("audit_ring"), Some(&1));

    assert_eq!(report.gap_control_count, 2);
    assert!((report.compliance_percentage - 33.333333333333336).abs() < 1e-6);
    assert!(report.is_healthy);
}

#[test]
fn test_text_sanitization() {
    assert_eq!(sanitize_telemetry_text("normal_text"), "normal_text");
    assert_eq!(sanitize_telemetry_text("control\x00\x07\x1bchars"), "controlchars");
    let long_text = "a".repeat(500);
    let sanitized = sanitize_telemetry_text(&long_text);
    assert_eq!(sanitized.len(), MAX_TELEMETRY_TEXT_LEN);
}

#[test]
fn test_policy_mode_reflection() {
    let mut svc = ComplianceService::new();
    let mut policy = ComplianceSecurityPolicy::default();
    policy.mode = CompliancePolicyMode::Enforcing;
    svc.set_policy(policy);

    let report = svc.observability_report(None).expect("report");
    assert_eq!(report.policy_mode, "enforcing");

    let mut policy2 = ComplianceSecurityPolicy::default();
    policy2.mode = CompliancePolicyMode::Permissive;
    svc.set_policy(policy2);
    let report2 = svc.observability_report(None).expect("report");
    assert_eq!(report2.policy_mode, "permissive");
}

#[test]
fn test_audit_ring_tail_correlation() {
    let svc = ComplianceService::new();
    let mut ring = AuditRing::open_in_memory().expect("open audit ring");

    let mut row1 = AuditRowInput::default();
    row1.tool = "aios.compliance".into();
    row1.command = "compliance register".into();
    ring.write(row1).expect("write row 1");

    let mut row2 = AuditRowInput::default();
    row2.tool = "aios.compliance.status".into();
    row2.command = "compliance status".into();
    ring.write(row2).expect("write row 2");

    let mut row_unrelated = AuditRowInput::default();
    row_unrelated.tool = "aios.secret".into();
    ring.write(row_unrelated).expect("write row 3");

    let report = svc.observability_report(Some(&ring)).expect("report");
    assert_eq!(report.recent_audit_events_count, 2);
}

#[test]
fn test_validation_negative_rfc3339_timestamp() {
    let svc = ComplianceService::new();
    let mut report = ComplianceObservabilityReport::generate(&svc, None).expect("valid report");

    report.generated_at_utc = "".to_string();
    let err1 = report.validate().unwrap_err();
    assert!(err1.contains(COMPOBS_ERR_VALIDATION));

    report.generated_at_utc = "not-a-timestamp".to_string();
    let err2 = report.validate().unwrap_err();
    assert!(err2.contains(COMPOBS_ERR_VALIDATION));
}

#[test]
fn test_validation_negative_percentage_nan_or_range() {
    let svc = ComplianceService::new();
    let mut report = ComplianceObservabilityReport::generate(&svc, None).expect("valid report");

    report.compliance_percentage = -5.0;
    assert!(report.validate().unwrap_err().contains(COMPOBS_ERR_VALIDATION));

    report.compliance_percentage = 105.0;
    assert!(report.validate().unwrap_err().contains(COMPOBS_ERR_VALIDATION));

    report.compliance_percentage = f64::NAN;
    assert!(report.validate().unwrap_err().contains(COMPOBS_ERR_VALIDATION));
}

#[test]
fn test_validation_negative_distribution_cardinality_bound() {
    let svc = ComplianceService::new();
    let mut report = ComplianceObservabilityReport::generate(&svc, None).expect("valid report");

    let mut map = HashMap::new();
    for i in 0..(MAX_OUTCOME_DISTRIBUTION_ENTRIES + 1) {
        map.insert(format!("fw_{}", i), 1);
    }
    report.mappings_by_framework = map;
    assert!(report.validate().unwrap_err().contains(COMPOBS_ERR_VALIDATION));
}

#[test]
fn test_validation_negative_control_chars_in_keys() {
    let svc = ComplianceService::new();
    let mut report = ComplianceObservabilityReport::generate(&svc, None).expect("valid report");

    report.mappings_by_framework.insert("bad\x07key".to_string(), 1);
    assert!(report.validate().unwrap_err().contains(COMPOBS_ERR_VALIDATION));
}

#[test]
fn test_capacity_utilization_boundary() {
    let mut svc = ComplianceService::new();
    let report_empty = svc.observability_report(None).expect("report");
    assert_eq!(report_empty.capacity_utilization_percent, 0);

    for i in 0..10 {
        let m = make_test_mapping(&format!("MAP-{}", i), ComplianceFramework::NistSp80053Rev5, ComplianceStatus::Compliant, SubstrateTargetType::PepGate);
        svc.register_mapping(m).expect("reg");
    }
    let report_10 = svc.observability_report(None).expect("report");
    assert_eq!(report_10.capacity_utilization_percent, 0); // 10 * 100 / 1024 = 0

    assert!(report_10.validate().is_ok());
}
