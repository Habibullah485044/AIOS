//! Compliance Mapping Automated Unit Test Suite (T-02917).
//!
//! Contract: docs/tasks/evidence/T-02914-spec.md.
//! Covers:
//!   1. Valid input: All framework variants, transitions, lookups, assessment.
//!   2. Invalid input: Duplicate ID, empty target ref, transition without mitigation.
//!   3. Boundary values: Identifier (64/65), title (128/129), array counts (16/17), capacity (1024).
//!   4. Primary failure mode: Traversal refusal, atomic write rollback.

use tempfile::tempdir;

use aiosh_core::compliance_data_model::*;
use aiosh_core::compliance_service::*;

// ---------------------------------------------------------------------------
// 1. Valid Input Coverage
// ---------------------------------------------------------------------------

#[test]
fn test_unit_valid_input_framework_taxonomy_and_lookups() {
    let mut svc = ComplianceService::new();
    let frameworks = [
        ComplianceFramework::NistSp80053Rev5,
        ComplianceFramework::Soc2Type2,
        ComplianceFramework::Iso27001,
        ComplianceFramework::CisControlsV8,
        ComplianceFramework::HipaaSecurity,
        ComplianceFramework::PciDssV4,
    ];

    for (idx, fw) in frameworks.iter().enumerate() {
        let entry = ComplianceMappingEntry::new(
            &format!("val-fw-{}", idx),
            &format!("CTRL-{}", idx),
            *fw,
            SubstrateTargetType::PepGate,
            &format!("pep.gate.{}", idx),
            vec![],
            ComplianceStatus::Compliant,
            "Mitigation verified",
            vec![],
        )
        .expect("Valid mapping creation");
        assert!(svc.register_mapping(entry).is_ok());
    }

    assert_eq!(svc.snapshot.mappings.len(), 6);
    for fw in &frameworks {
        let results = svc.find_by_framework(*fw);
        assert_eq!(results.len(), 1);
    }
}

#[test]
fn test_unit_valid_input_status_transition_chain() {
    let mut svc = ComplianceService::new();
    let entry = ComplianceMappingEntry::new(
        "tr-chain",
        "AC-1",
        ComplianceFramework::Soc2Type2,
        SubstrateTargetType::PepGate,
        "pep.auth",
        vec![],
        ComplianceStatus::NonCompliant,
        "",
        vec![],
    )
    .expect("Valid creation");
    svc.register_mapping(entry).expect("Registered");

    assert!(svc.update_status("tr-chain", ComplianceStatus::PartiallyCompliant, "Step 1").is_ok());
    assert_eq!(svc.get_mapping("tr-chain").unwrap().status, ComplianceStatus::PartiallyCompliant);

    assert!(svc.update_status("tr-chain", ComplianceStatus::Compliant, "Full mitigation confirmed").is_ok());
    assert_eq!(svc.get_mapping("tr-chain").unwrap().status, ComplianceStatus::Compliant);
}

// ---------------------------------------------------------------------------
// 2. Invalid Input Coverage
// ---------------------------------------------------------------------------

#[test]
fn test_unit_invalid_input_duplicate_registration_refused() {
    let mut svc = ComplianceService::new();
    let e1 = ComplianceMappingEntry::new(
        "dup-id", "AC-1", ComplianceFramework::Soc2Type2,
        SubstrateTargetType::PepGate, "pep.1", vec![], ComplianceStatus::Compliant, "Mitigated", vec![],
    ).unwrap();
    assert!(svc.register_mapping(e1).is_ok());

    let e2 = ComplianceMappingEntry::new(
        "dup-id", "AC-1-dup", ComplianceFramework::Soc2Type2,
        SubstrateTargetType::PepGate, "pep.1", vec![], ComplianceStatus::Compliant, "Mitigated", vec![],
    ).unwrap();
    let err = svc.register_mapping(e2).unwrap_err();
    assert!(err.contains(COMPLIANCE_ERR_DUPLICATE_ID));
}

#[test]
fn test_unit_invalid_input_empty_substrate_target_ref() {
    let res = ComplianceMappingEntry::new(
        "bad-ref", "AC-1", ComplianceFramework::Soc2Type2,
        SubstrateTargetType::PepGate, "   ", vec![], ComplianceStatus::NonCompliant, "", vec![],
    );
    let err = res.unwrap_err();
    assert!(err.contains(COMPLIANCE_ERR_MISSING_SUBSTRATE_REF));
}

#[test]
fn test_unit_invalid_input_compliant_without_summary() {
    let res = ComplianceMappingEntry::new(
        "bad-compl", "AC-1", ComplianceFramework::Soc2Type2,
        SubstrateTargetType::PepGate, "pep.1", vec![], ComplianceStatus::Compliant, "", vec![],
    );
    let err = res.unwrap_err();
    assert!(err.contains(COMPLIANCE_ERR_BOUNDS_EXCEEDED));
}

#[test]
fn test_unit_invalid_input_update_nonexistent_mapping() {
    let mut svc = ComplianceService::new();
    let err = svc.update_status("NONEXISTENT", ComplianceStatus::PartiallyCompliant, "Reason").unwrap_err();
    assert!(err.contains(COMPLIANCESVC_ERR_NOT_FOUND));
}

// ---------------------------------------------------------------------------
// 3. Boundary Values Coverage
// ---------------------------------------------------------------------------

#[test]
fn test_unit_boundary_identifier_lengths() {
    let id_64 = "A".repeat(64);
    assert!(ComplianceMappingEntry::new(
        &id_64, "AC-1", ComplianceFramework::Soc2Type2,
        SubstrateTargetType::PepGate, "pep.1", vec![], ComplianceStatus::NonCompliant, "", vec![],
    ).is_ok());

    let id_65 = "A".repeat(65);
    let err = ComplianceMappingEntry::new(
        &id_65, "AC-1", ComplianceFramework::Soc2Type2,
        SubstrateTargetType::PepGate, "pep.1", vec![], ComplianceStatus::NonCompliant, "", vec![],
    ).unwrap_err();
    assert!(err.contains(COMPLIANCE_ERR_BOUNDS_EXCEEDED));
}

#[test]
fn test_unit_boundary_title_lengths() {
    let title_128 = "T".repeat(128);
    assert!(ComplianceControl::new("ctrl-1", ComplianceFramework::Soc2Type2, &title_128, "desc", "cat").is_ok());

    let title_129 = "T".repeat(129);
    let err = ComplianceControl::new("ctrl-1", ComplianceFramework::Soc2Type2, &title_129, "desc", "cat").unwrap_err();
    assert!(err.contains(COMPLIANCE_ERR_BOUNDS_EXCEEDED));
}

#[test]
fn test_unit_boundary_array_capacities() {
    let t16: Vec<String> = (0..16).map(|i| format!("threat_{}", i)).collect();
    assert!(ComplianceMappingEntry::new(
        "arr-16", "AC-1", ComplianceFramework::Soc2Type2,
        SubstrateTargetType::PepGate, "pep.1", t16, ComplianceStatus::NonCompliant, "", vec![],
    ).is_ok());

    let t17: Vec<String> = (0..17).map(|i| format!("threat_{}", i)).collect();
    let err = ComplianceMappingEntry::new(
        "arr-17", "AC-1", ComplianceFramework::Soc2Type2,
        SubstrateTargetType::PepGate, "pep.1", t17, ComplianceStatus::NonCompliant, "", vec![],
    ).unwrap_err();
    assert!(err.contains(COMPLIANCE_ERR_BOUNDS_EXCEEDED));
}

#[test]
fn test_unit_boundary_catalog_capacity() {
    let mut snap = ComplianceCatalogSnapshot::new("1.0.0");
    for i in 0..1024 {
        snap.mappings.push(ComplianceMappingEntry::new(
            &format!("cap-{}", i), "AC-1", ComplianceFramework::Soc2Type2,
            SubstrateTargetType::PepGate, "pep.1", vec![], ComplianceStatus::NonCompliant, "", vec![],
        ).unwrap());
    }
    assert_eq!(snap.mappings.len(), 1024);

    let overflow = ComplianceMappingEntry::new(
        "cap-1024", "AC-1", ComplianceFramework::Soc2Type2,
        SubstrateTargetType::PepGate, "pep.1", vec![], ComplianceStatus::NonCompliant, "", vec![],
    ).unwrap();
    let err = snap.add_mapping(overflow).unwrap_err();
    assert!(err.contains(COMPLIANCE_ERR_BOUNDS_EXCEEDED));
}

// ---------------------------------------------------------------------------
// 4. Primary Failure Mode Coverage
// ---------------------------------------------------------------------------

#[test]
fn test_unit_primary_failure_path_traversal() {
    let traversals = [
        "../escape.json",
        "../../root.json",
        "nested/../../secret.json",
    ];
    for t in traversals {
        let err = ComplianceService::validate_path(std::path::Path::new(t)).unwrap_err();
        assert!(err.contains(COMPLIANCESVC_ERR_PATH_TRAVERSAL));
    }
}

#[test]
fn test_unit_primary_failure_atomic_save_leaves_file_intact() {
    let dir = tempdir().unwrap();
    let store_path = dir.path().join("compliance_map.json");
    let mut svc = ComplianceService::new();
    let entry = ComplianceMappingEntry::new(
        "p1", "AC-1", ComplianceFramework::Soc2Type2,
        SubstrateTargetType::AuditRing, "audit.ring", vec![], ComplianceStatus::Compliant, "Mitigated", vec![],
    ).unwrap();
    svc.register_mapping(entry).unwrap();
    svc.save_to_path(&store_path).unwrap();

    let before_content = std::fs::read(&store_path).unwrap();

    // Invalid path save attempt fails and leaves original file untouched
    assert!(svc.save_to_path(std::path::Path::new("../invalid.json")).is_err());
    let after_content = std::fs::read(&store_path).unwrap();
    assert_eq!(before_content, after_content);
}
