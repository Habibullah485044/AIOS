//! Integration Tests for Compliance Mapping Core Service (T-02816).

use tempfile::tempdir;

use aiosh_core::compliance_data_model::*;
use aiosh_core::compliance_service::*;
use aiosh_core::threat_model_service::ThreatModelService;

#[test]
fn test_compliance_service_end_to_end_lifecycle() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().join("compliance_map.json");

    // 1. Initialize service with canonical baseline and persist
    let service = ComplianceService::with_canonical_baseline();
    assert!(!service.snapshot.mappings.is_empty());
    service.save_to_path(&store_path).expect("initial save");

    // 2. Load from disk and verify persistence fidelity
    let mut reloaded = ComplianceService::load_from_path(&store_path).expect("reload");
    assert_eq!(reloaded.snapshot.mappings.len(), service.snapshot.mappings.len());

    // 3. Register additional mapping bound to Threat Model
    let threat_svc = ThreatModelService::with_canonical_threats();
    let first_threat = &threat_svc.snapshot.threats[0];

    let new_entry = ComplianceMappingEntry::new(
        "MAP-ISO-A8-LOGGING",
        "A.8.15",
        ComplianceFramework::Iso27001,
        SubstrateTargetType::AuditRing,
        "audit_ring_commit",
        vec![first_threat.id.clone()],
        ComplianceStatus::Compliant,
        "Logged via tamper-evident audit ring",
        vec!["iso27001".to_string(), "logging".to_string()],
    ).unwrap();

    reloaded.register_mapping(new_entry).expect("register ISO mapping");
    reloaded.save_to_path(&store_path).expect("save updated");

    // 4. Perform framework-specific assessment
    let iso_assessment = reloaded.assess_framework(Some(ComplianceFramework::Iso27001));
    assert_eq!(iso_assessment.total_mappings, 1);
    assert_eq!(iso_assessment.compliant_count, 1);
    assert_eq!(iso_assessment.compliance_percentage, 100.0);

    // 5. Perform global assessment
    let global_assessment = reloaded.assess_framework(None);
    assert_eq!(global_assessment.total_mappings, service.snapshot.mappings.len() + 1);
    assert_eq!(global_assessment.compliance_percentage, 100.0);

    // 6. Verify PEP enforcement coverage
    assert!(reloaded.verify_pep_coverage("pep_enforce_gate"));
}
