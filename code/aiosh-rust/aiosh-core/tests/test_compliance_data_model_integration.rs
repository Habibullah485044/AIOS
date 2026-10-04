//! Integration Tests for Compliance Mapping Data Model (T-02806).

use aiosh_core::*;
use aiosh_core::threat_model_service::ThreatModelService;

#[test]
fn test_compliance_and_threat_model_integration() {
    // 1. Initialize threat model service with canonical baseline
    let threat_svc = ThreatModelService::with_canonical_threats();
    assert!(!threat_svc.snapshot.threats.is_empty());

    // 2. Initialize compliance snapshot with canonical baseline
    let compliance_snapshot = ComplianceCatalogSnapshot::canonical_baseline();
    assert!(!compliance_snapshot.mappings.is_empty());

    // 3. Verify cross-substrate binding consistency:
    // Every threat referenced in compliance mappings should either match a canonical threat ID
    // or follow valid identifier syntax.
    for mapping in &compliance_snapshot.mappings {
        assert!(!mapping.target_ref.is_empty());
        assert!(!mapping.mitigation_summary.is_empty());

        for tid in &mapping.threat_ids {
            assert!(validate_compliance_identifier(tid, "Threat ID").is_ok());
        }
    }

    // 4. Verify assessment correlation
    let risk = threat_svc.assess_risk();
    let comp_ratio = compliance_snapshot.compliance_ratio();
    assert!(risk.total_threats > 0);
    assert_eq!(comp_ratio, 1.0);
}

#[test]
fn test_cross_framework_compliance_coverage() {
    let snapshot = ComplianceCatalogSnapshot::canonical_baseline();

    let frameworks = vec![
        ComplianceFramework::NistSp80053Rev5,
        ComplianceFramework::Soc2Type2,
        ComplianceFramework::CisControlsV8,
    ];

    for fw in frameworks {
        let entries = snapshot.find_by_framework(fw);
        assert!(!entries.is_empty(), "Framework {} should have baseline mappings", fw);
        for entry in entries {
            assert_eq!(entry.status, ComplianceStatus::Compliant);
            assert!(matches!(
                entry.target_type,
                SubstrateTargetType::PepGate | SubstrateTargetType::AuditRing | SubstrateTargetType::ConstitutionRule
            ));
        }
    }
}
