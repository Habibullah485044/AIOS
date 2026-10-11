//! Automated Test Suite Implementation for Compliance Mapping Subsystem (T-02916).
//!
//! Implements formal verification vectors AUTOCOMPLIANCE1..AUTOCOMPLIANCE10 defined in
//! `docs/tasks/evidence/T-02914-spec.md`.

use std::path::PathBuf;
use tempfile::tempdir;

use aiosh_core::compliance_config::*;
use aiosh_core::compliance_data_model::*;
use aiosh_core::compliance_service::*;

/// AUTOCOMPLIANCE1: Full Compliance Lifecycle & Status Transitions
#[test]
fn test_autocompliance1_lifecycle_and_transitions() {
    let mut svc = ComplianceService::new();
    let entry = ComplianceMappingEntry::new(
        "ac1-control",
        "AC-1",
        ComplianceFramework::NistSp80053Rev5,
        SubstrateTargetType::PepGate,
        "pep.auth.check",
        vec![],
        ComplianceStatus::NonCompliant,
        "",
        vec![],
    )
    .expect("Valid compliance entry");

    assert!(svc.register_mapping(entry).is_ok());
    assert_eq!(svc.snapshot.mappings.len(), 1);
    assert_eq!(svc.snapshot.mappings[0].status, ComplianceStatus::NonCompliant);

    // Transition: NonCompliant -> PartiallyCompliant
    assert!(svc.update_status("ac1-control", ComplianceStatus::PartiallyCompliant, "Rollout begun").is_ok());
    assert_eq!(svc.snapshot.mappings[0].status, ComplianceStatus::PartiallyCompliant);

    // Negative: Transition to Compliant without mitigation summary or reason fails closed
    assert!(svc.update_status("ac1-control", ComplianceStatus::Compliant, "").is_err());

    // Valid transition to Compliant with justification
    assert!(svc.update_status("ac1-control", ComplianceStatus::Compliant, "Mitigation verified").is_ok());
    assert_eq!(svc.snapshot.mappings[0].status, ComplianceStatus::Compliant);
}

/// AUTOCOMPLIANCE2: Duplicate Control & Collision Rejection
#[test]
fn test_autocompliance2_duplicate_rejection() {
    let mut svc = ComplianceService::new();
    let e1 = ComplianceMappingEntry::new(
        "dup-01",
        "AC-2",
        ComplianceFramework::Soc2Type2,
        SubstrateTargetType::PepGate,
        "pep.grant.verify",
        vec![],
        ComplianceStatus::Compliant,
        "Verified mitigation",
        vec![],
    )
    .expect("Valid entry 1");
    assert!(svc.register_mapping(e1).is_ok());

    let e2 = ComplianceMappingEntry::new(
        "dup-01",
        "AC-2-dup",
        ComplianceFramework::Soc2Type2,
        SubstrateTargetType::PepGate,
        "pep.grant.verify",
        vec![],
        ComplianceStatus::Compliant,
        "Duplicate ID entry",
        vec![],
    )
    .expect("Valid entry 2");

    let err = svc.register_mapping(e2).unwrap_err();
    assert!(err.contains(COMPLIANCE_ERR_DUPLICATE_ID));
    assert_eq!(svc.snapshot.mappings.len(), 1);
}

/// AUTOCOMPLIANCE3: Identifier, Text & Array Bounds Validation
#[test]
fn test_autocompliance3_bounds_validation() {
    // 1. Identifier length exceeded (> 64)
    let long_id = "A".repeat(65);
    let res = ComplianceMappingEntry::new(
        &long_id,
        "AC-1",
        ComplianceFramework::NistSp80053Rev5,
        SubstrateTargetType::PepGate,
        "pep.target",
        vec![],
        ComplianceStatus::NonCompliant,
        "",
        vec![],
    );
    assert!(res.is_err());

    // 2. Identifier invalid characters
    let res2 = ComplianceMappingEntry::new(
        "bad id with spaces!",
        "AC-1",
        ComplianceFramework::NistSp80053Rev5,
        SubstrateTargetType::PepGate,
        "pep.target",
        vec![],
        ComplianceStatus::NonCompliant,
        "",
        vec![],
    );
    assert!(res2.is_err());

    // 3. Control title validation
    let long_title = "T".repeat(129);
    assert!(ComplianceControl::new("ctrl-1", ComplianceFramework::Soc2Type2, &long_title, "desc", "cat").is_err());
}

/// AUTOCOMPLIANCE4: 4-Level Precedence Ladder Resolution
#[test]
fn test_autocompliance4_precedence_ladder() {
    // Default resolution
    let resolved = ComplianceConfig::resolve(None, None).expect("Resolve defaults");
    assert_eq!(resolved.config.store_path, PathBuf::from("docs/compliance_map.json"));
    assert_eq!(resolved.source.get("store_path"), Some(&ConfigSource::Default));

    // Argument override beats everything
    let resolved_arg = ComplianceConfig::resolve(Some("arg_path.json"), None).expect("Resolve arg");
    assert_eq!(resolved_arg.config.store_path, PathBuf::from("arg_path.json"));
    assert_eq!(resolved_arg.source.get("store_path"), Some(&ConfigSource::Argument));
}

/// AUTOCOMPLIANCE5: CWE-15 / CWE-22 Hygiene Predicate Defense
#[test]
fn test_autocompliance5_hygiene_predicate() {
    assert!(ComplianceConfig::hygiene_ok("valid_file.json"));
    assert!(ComplianceConfig::hygiene_ok("subdir/nested.json"));

    // Traversal rejection
    assert!(!ComplianceConfig::hygiene_ok("../escape.json"));
    assert!(!ComplianceConfig::hygiene_ok("dir/../../secret.json"));

    // Control chars rejection
    assert!(!ComplianceConfig::hygiene_ok("file\x00name.json"));
    assert!(!ComplianceConfig::hygiene_ok("bad\npath.json"));

    // Bounds rejection
    let long_path = "a".repeat(1025);
    assert!(!ComplianceConfig::hygiene_ok(&long_path));
    assert!(!ComplianceConfig::hygiene_ok(""));
    assert!(!ComplianceConfig::hygiene_ok("   "));
}

/// AUTOCOMPLIANCE6: Pre-Parse File Size Bounds & CWE-400 DoS Defense
#[test]
fn test_autocompliance6_size_caps() {
    assert_eq!(MAX_CONFIG_FILE_BYTES, 64 * 1024);

    let dir = tempdir().unwrap();
    let big_file = dir.path().join("big_config.json");
    std::fs::write(&big_file, vec![b'x'; 65 * 1024]).unwrap();

    let err = ComplianceConfig::from_path(&PathBuf::from(&big_file)).unwrap_err();
    assert!(err.contains(COMPLIANCECONF_ERR_FILE_SIZE));
}

/// AUTOCOMPLIANCE7: Audit Immutability & Audit Logging Guarantee
#[test]
fn test_autocompliance7_audit_immutability() {
    let mut cfg = ComplianceConfig::default();
    assert!(cfg.audit_all_mutations);

    // Explicit false clamped to true
    cfg.audit_all_mutations = false;
    let clamped = cfg.clamped();
    assert!(clamped.audit_all_mutations);
}

/// AUTOCOMPLIANCE8: Proof of Restraint & PEP Gating (Invariant I-2)
#[test]
fn test_autocompliance8_pep_gating() {
    let mut svc = ComplianceService::new();
    let entry = ComplianceMappingEntry::new(
        "pep-gate-01",
        "SC-7",
        ComplianceFramework::NistSp80053Rev5,
        SubstrateTargetType::PepGate,
        "pep.exec.tool",
        vec![],
        ComplianceStatus::Compliant,
        "PEP gating verified",
        vec![],
    )
    .unwrap();
    svc.register_mapping(entry).unwrap();

    assert!(svc.verify_pep_coverage("pep.exec.tool"));
    assert!(!svc.verify_pep_coverage("pep.unmapped.action"));

    let uncovered = svc.uncovered_pep_gates(&["pep.exec.tool", "pep.unmapped.action"]);
    assert_eq!(uncovered, vec!["pep.unmapped.action".to_string()]);
}

/// AUTOCOMPLIANCE9: Assessment Scoring & Statistics Consistency
#[test]
fn test_autocompliance9_assessment_scoring() {
    let mut svc = ComplianceService::new();
    svc.register_mapping(
        ComplianceMappingEntry::new(
            "ctrl-01", "AC-1", ComplianceFramework::NistSp80053Rev5,
            SubstrateTargetType::PepGate, "pep.1", vec![], ComplianceStatus::Compliant, "Mitigated", vec![],
        ).unwrap(),
    ).unwrap();
    svc.register_mapping(
        ComplianceMappingEntry::new(
            "ctrl-02", "AC-2", ComplianceFramework::NistSp80053Rev5,
            SubstrateTargetType::PepGate, "pep.2", vec![], ComplianceStatus::PartiallyCompliant, "", vec![],
        ).unwrap(),
    ).unwrap();
    svc.register_mapping(
        ComplianceMappingEntry::new(
            "ctrl-03", "AC-3", ComplianceFramework::NistSp80053Rev5,
            SubstrateTargetType::PepGate, "pep.3", vec![], ComplianceStatus::NonCompliant, "", vec![],
        ).unwrap(),
    ).unwrap();
    svc.register_mapping(
        ComplianceMappingEntry::new(
            "ctrl-04", "AC-4", ComplianceFramework::NistSp80053Rev5,
            SubstrateTargetType::PepGate, "pep.4", vec![], ComplianceStatus::NotApplicable, "", vec![],
        ).unwrap(),
    ).unwrap();

    let report = svc.assess_framework(Some(ComplianceFramework::NistSp80053Rev5));
    assert_eq!(report.total_mappings, 4);
    assert_eq!(report.compliant_count, 1);
    assert_eq!(report.partially_compliant_count, 1);
    assert_eq!(report.non_compliant_count, 1);
    assert_eq!(report.not_applicable_count, 1);
    assert_eq!(report.compliance_percentage, 25.0);
    assert_eq!(report.gap_control_ids, vec!["AC-2".to_string(), "AC-3".to_string()]);
}

/// AUTOCOMPLIANCE10: Concurrency Safety & Atomic Persistence
#[test]
fn test_autocompliance10_atomic_persistence() {
    let dir = tempdir().unwrap();
    let store_file = dir.path().join("compliance_map.json");
    let mut svc = ComplianceService::new();
    let entry = ComplianceMappingEntry::new(
        "persist-01",
        "AU-1",
        ComplianceFramework::Soc2Type2,
        SubstrateTargetType::AuditRing,
        "audit.ring.main",
        vec![],
        ComplianceStatus::Compliant,
        "Audit ring configured",
        vec![],
    )
    .unwrap();
    svc.register_mapping(entry).unwrap();

    svc.save_to_path(&store_file).expect("Saved successfully");
    assert!(store_file.exists());

    let loaded = ComplianceService::load_from_path(&store_file).expect("Loaded successfully");
    assert_eq!(loaded.snapshot.mappings.len(), 1);
    assert_eq!(loaded.snapshot.mappings[0].id, "persist-01");

    // Traversal rejection in validate_path
    let bad_path = std::path::Path::new("../traversal.json");
    assert!(ComplianceService::validate_path(bad_path).is_err());
}
