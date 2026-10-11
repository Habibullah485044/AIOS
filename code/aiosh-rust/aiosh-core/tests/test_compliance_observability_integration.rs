//! Integration Tests for Compliance Mapping Observability (T-02938).

use tempfile::tempdir;

use aiosh_core::audit::{AuditRing, AuditRowInput};
use aiosh_core::compliance_data_model::{
    ComplianceFramework, ComplianceMappingEntry, ComplianceStatus, SubstrateTargetType,
};
use aiosh_core::compliance_observability::ComplianceObservabilityReport;
use aiosh_core::compliance_policy::{ComplianceSecurityPolicy, CompliancePolicyMode};
use aiosh_core::compliance_service::ComplianceService;

fn make_mapping(id: &str, fw: ComplianceFramework, st: ComplianceStatus, tt: SubstrateTargetType) -> ComplianceMappingEntry {
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
    .expect("valid entry")
}

#[test]
fn test_compliance_observability_end_to_end_integration() {
    let tmp = tempdir().expect("tempdir");
    let store_path = tmp.path().join("compliance_map_integrated.json");

    // 1. Initialize service and register mappings
    let mut service = ComplianceService::new();
    let m1 = make_mapping("MAP-01", ComplianceFramework::NistSp80053Rev5, ComplianceStatus::Compliant, SubstrateTargetType::PepGate);
    let m2 = make_mapping("MAP-02", ComplianceFramework::Iso27001, ComplianceStatus::NonCompliant, SubstrateTargetType::AuditRing);
    let m3 = make_mapping("MAP-03", ComplianceFramework::Soc2Type2, ComplianceStatus::PartiallyCompliant, SubstrateTargetType::PepGate);

    service.register_mapping(m1).expect("reg 1");
    service.register_mapping(m2).expect("reg 2");
    service.register_mapping(m3).expect("reg 3");

    let mut policy = ComplianceSecurityPolicy::default();
    policy.mode = CompliancePolicyMode::Enforcing;
    service.set_policy(policy);

    // 2. Persist to disk and reload in a fresh service
    service.save_to_path(&store_path).expect("save succeeded");
    let mut loaded_service = ComplianceService::load_from_path(&store_path).expect("load succeeded");
    let mut policy2 = ComplianceSecurityPolicy::default();
    policy2.mode = CompliancePolicyMode::Enforcing;
    loaded_service.set_policy(policy2);

    // 3. Populate audit ring
    let mut ring = AuditRing::open_in_memory().expect("open audit ring");

    let mut row1 = AuditRowInput::default();
    row1.tool = "aios.compliance".into();
    row1.command = "compliance register".into();
    ring.write(row1).expect("write row 1");

    let mut row2 = AuditRowInput::default();
    row2.tool = "aios.compliance".into();
    row2.command = "compliance status".into();
    ring.write(row2).expect("write row 2");

    let mut row_other = AuditRowInput::default();
    row_other.tool = "aios.task".into();
    ring.write(row_other).expect("write row 3");

    // 4. Generate observability report
    let report = loaded_service.observability_report(Some(&ring)).expect("report succeeds");

    assert_eq!(report.total_mappings, 3);
    assert_eq!(report.policy_mode, "enforcing");
    assert!(report.is_healthy);
    assert_eq!(report.recent_audit_events_count, 2);
    assert_eq!(report.mappings_by_framework.get("nist_sp_800_53_rev5"), Some(&1));
    assert_eq!(report.mappings_by_framework.get("iso_27001_2022"), Some(&1));
    assert_eq!(report.mappings_by_framework.get("soc2_type2"), Some(&1));
    assert_eq!(report.mappings_by_status.get("compliant"), Some(&1));
    assert_eq!(report.mappings_by_status.get("non_compliant"), Some(&1));
    assert_eq!(report.mappings_by_status.get("partially_compliant"), Some(&1));
    assert_eq!(report.mappings_by_target_type.get("pep_gate"), Some(&2));
    assert_eq!(report.mappings_by_target_type.get("audit_ring"), Some(&1));

    // 5. Test JSON round-trip serialization parity
    let json_str = serde_json::to_string(&report).expect("serialize report");
    let deserialized: ComplianceObservabilityReport = serde_json::from_str(&json_str).expect("deserialize report");
    assert_eq!(report, deserialized);
    assert!(deserialized.validate().is_ok());
}
