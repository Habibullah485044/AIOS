//! Unit Tests for Compliance Mapping Data Model (T-02805).

use aiosh_core::compliance_data_model::*;

#[test]
fn test_compliance_control_validation() {
    let ctrl = ComplianceControl::new(
        "AC-3",
        ComplianceFramework::NistSp80053Rev5,
        "Access Enforcement",
        "Enforces approved authorizations for logical access to information.",
        "Access Control",
    ).expect("valid control");
    assert_eq!(ctrl.id, "AC-3");
    assert_eq!(ctrl.framework, ComplianceFramework::NistSp80053Rev5);

    // Negative: empty ID
    let err_empty_id = ComplianceControl::new(
        "",
        ComplianceFramework::NistSp80053Rev5,
        "Title",
        "Desc",
        "Cat",
    );
    assert!(err_empty_id.is_err());
    assert!(err_empty_id.unwrap_err().contains(COMPLIANCE_ERR_INVALID_ID));

    // Negative: control characters in title
    let err_ctrl_char = ComplianceControl::new(
        "AC-3",
        ComplianceFramework::NistSp80053Rev5,
        "Title\x00WithNull",
        "Desc",
        "Cat",
    );
    assert!(err_ctrl_char.is_err());
    assert!(err_ctrl_char.unwrap_err().contains(COMPLIANCE_ERR_CONTROL_CHARS));
}

#[test]
fn test_compliance_mapping_entry_validation() {
    let entry = ComplianceMappingEntry::new(
        "MAP-SOC2-CC61",
        "CC6.1",
        ComplianceFramework::Soc2Type2,
        SubstrateTargetType::PepGate,
        "capability_grant_gate",
        vec!["T-EOP-001".to_string()],
        ComplianceStatus::Compliant,
        "Protected via cryptographic capability token checks.",
        vec!["access".to_string()],
    ).expect("valid mapping");

    assert_eq!(entry.id, "MAP-SOC2-CC61");
    assert_eq!(entry.status, ComplianceStatus::Compliant);

    // Negative: compliant status with empty mitigation summary
    let err_no_mitigation = ComplianceMappingEntry::new(
        "MAP-SOC2-CC62",
        "CC6.2",
        ComplianceFramework::Soc2Type2,
        SubstrateTargetType::PepGate,
        "capability_grant_gate",
        vec![],
        ComplianceStatus::Compliant,
        "   ",
        vec![],
    );
    assert!(err_no_mitigation.is_err());
    assert!(err_no_mitigation.unwrap_err().contains(COMPLIANCE_ERR_BOUNDS_EXCEEDED));

    // Negative: empty target_ref
    let err_empty_target = ComplianceMappingEntry::new(
        "MAP-SOC2-CC63",
        "CC6.3",
        ComplianceFramework::Soc2Type2,
        SubstrateTargetType::PepGate,
        "  ",
        vec![],
        ComplianceStatus::NonCompliant,
        "Pending implementation",
        vec![],
    );
    assert!(err_empty_target.is_err());
    assert!(err_empty_target.unwrap_err().contains(COMPLIANCE_ERR_MISSING_SUBSTRATE_REF));
}

#[test]
fn test_compliance_status_transitions() {
    let mut entry = ComplianceMappingEntry::new(
        "MAP-CIS-1",
        "CIS-1",
        ComplianceFramework::CisControlsV8,
        SubstrateTargetType::PepGate,
        "inventory_gate",
        vec![],
        ComplianceStatus::NonCompliant,
        "Initial assessment",
        vec![],
    ).unwrap();

    assert_eq!(entry.status, ComplianceStatus::NonCompliant);

    // Transition to PartiallyCompliant
    entry.transition_to(ComplianceStatus::PartiallyCompliant, "Phase 1 deployed").unwrap();
    assert_eq!(entry.status, ComplianceStatus::PartiallyCompliant);

    // Transition to Compliant
    entry.transition_to(ComplianceStatus::Compliant, "Full hardware attestation verified").unwrap();
    assert_eq!(entry.status, ComplianceStatus::Compliant);
}

#[test]
fn test_compliance_snapshot_baseline_and_queries() {
    let snapshot = ComplianceCatalogSnapshot::canonical_baseline();
    assert!(!snapshot.mappings.is_empty());

    // Query by framework
    let nist_mappings = snapshot.find_by_framework(ComplianceFramework::NistSp80053Rev5);
    assert!(!nist_mappings.is_empty());
    assert!(nist_mappings.iter().any(|m| m.control_id == "AC-3"));

    // Query by control
    let ac3 = snapshot.find_by_control("AC-3");
    assert_eq!(ac3.len(), 1);

    // Query by target
    let pep_targets = snapshot.find_by_target("pep_enforce_gate");
    assert_eq!(pep_targets.len(), 1);

    // Query by status
    let compliant_list = snapshot.find_by_status(ComplianceStatus::Compliant);
    assert_eq!(compliant_list.len(), snapshot.mappings.len());

    assert_eq!(snapshot.compliance_ratio(), 1.0);
}

#[test]
fn test_compliance_snapshot_duplicate_detection() {
    let mut snapshot = ComplianceCatalogSnapshot::new("1.0.0");
    let entry1 = ComplianceMappingEntry::new(
        "MAP-TEST-001",
        "CTRL-1",
        ComplianceFramework::Iso27001,
        SubstrateTargetType::PepGate,
        "gate_1",
        vec![],
        ComplianceStatus::NonCompliant,
        "None",
        vec![],
    ).unwrap();
    snapshot.add_mapping(entry1.clone()).unwrap();

    // Duplicate ID must fail
    let err_dup = snapshot.add_mapping(entry1);
    assert!(err_dup.is_err());
    assert!(err_dup.unwrap_err().contains(COMPLIANCE_ERR_DUPLICATE_ID));
}

#[test]
fn test_compliance_snapshot_serde_roundtrip() {
    let snapshot = ComplianceCatalogSnapshot::canonical_baseline();
    let json_str = serde_json::to_string(&snapshot).expect("serialize");
    let restored: ComplianceCatalogSnapshot = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(snapshot, restored);
}
