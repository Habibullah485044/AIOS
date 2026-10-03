//! Integration Tests for Threat Model Security Policy (T-02766).

use tempfile::tempdir;

use aiosh_core::threat_model_data_model::{ThreatCategory, ThreatEntry, ThreatSeverity, ThreatStatus};
use aiosh_core::threat_model_policy::{
    ThreatModelSecurityPolicy, ThreatPolicyMode,
    THREATPOL_ERR_CATEGORY_PROHIBITED, THREATPOL_ERR_CRITICAL_UNMITIGATED,
    THREATPOL_ERR_CWE_REQUIRED, THREATPOL_ERR_DENIED,
};
use aiosh_core::threat_model_service::ThreatModelService;

fn create_valid_entry(id: &str, category: ThreatCategory, severity: ThreatSeverity, cwe: &str) -> ThreatEntry {
    ThreatEntry::new(
        id,
        &format!("Threat {}", id),
        "Threat description for integration testing",
        category,
        severity,
        "kernel.threat.component",
        vec![cwe.to_string()],
        vec![],
    )
    .expect("valid entry")
}

#[test]
fn test_threat_policy_end_to_end_service_integration() {
    let mut svc = ThreatModelService::new();

    // 1. Establish restrictive security policy
    let mut policy = ThreatModelSecurityPolicy::default();
    policy.mode = ThreatPolicyMode::Enforcing;
    policy.require_cwe_mapping = true;
    policy.disallow_unmitigated_critical = true;
    policy.prohibited_categories = vec![ThreatCategory::Repudiation];
    svc.set_policy(policy);

    assert!(svc.policy().is_some());
    assert_eq!(svc.policy().unwrap().mode, ThreatPolicyMode::Enforcing);

    // 2. Prohibited category is rejected fail-closed
    let prohibited_entry = create_valid_entry(
        "THREAT-REP-01",
        ThreatCategory::Repudiation,
        ThreatSeverity::Medium,
        "CWE-284",
    );
    let err_prohibited = svc.register_threat(prohibited_entry).unwrap_err();
    assert!(
        err_prohibited.contains(THREATPOL_ERR_CATEGORY_PROHIBITED),
        "Expected category prohibited, got: {}",
        err_prohibited
    );

    // 3. Threat without CWE is rejected fail-closed
    let no_cwe_entry = ThreatEntry::new(
        "THREAT-NOCWE-01",
        "Threat No CWE",
        "Description without CWE",
        ThreatCategory::Tampering,
        ThreatSeverity::High,
        "kernel.threat.component",
        vec![],
        vec![],
    )
    .expect("valid struct");
    let err_cwe = svc.register_threat(no_cwe_entry).unwrap_err();
    assert!(
        err_cwe.contains(THREATPOL_ERR_CWE_REQUIRED),
        "Expected CWE required, got: {}",
        err_cwe
    );

    // 4. Compliant critical threat registration succeeds
    let crit_entry = create_valid_entry(
        "THREAT-CRIT-99",
        ThreatCategory::ElevationOfPrivilege,
        ThreatSeverity::Critical,
        "CWE-269",
    );
    assert!(svc.register_threat(crit_entry).is_ok());
    assert_eq!(svc.list_threats().len(), 1);

    // 5. Unmitigated critical threat transition to Accepted fails closed under policy
    let err_accept = svc.update_status("THREAT-CRIT-99", ThreatStatus::Accepted).unwrap_err();
    assert!(
        err_accept.contains(THREATPOL_ERR_CRITICAL_UNMITIGATED),
        "Expected critical unmitigated error, got: {}",
        err_accept
    );

    // 6. Attaching empty mitigation fails closed under policy
    let err_mit = svc.attach_mitigation("THREAT-CRIT-99", "   ").unwrap_err();
    assert!(
        err_mit.contains(THREATPOL_ERR_DENIED),
        "Expected empty mitigation denied, got: {}",
        err_mit
    );

    // 7. Attaching valid mitigation succeeds
    assert!(svc.attach_mitigation("THREAT-CRIT-99", "Mandatory ASLR + Non-executable stack").is_ok());

    // 8. Now transition to Accepted succeeds, and subsequent transition to Resolved succeeds
    assert!(svc.update_status("THREAT-CRIT-99", ThreatStatus::Accepted).is_ok());
    assert_eq!(svc.get_threat("THREAT-CRIT-99").unwrap().status, ThreatStatus::Accepted);
    assert!(svc.update_status("THREAT-CRIT-99", ThreatStatus::Resolved).is_ok());
    assert_eq!(svc.get_threat("THREAT-CRIT-99").unwrap().status, ThreatStatus::Resolved);

    // 9. Permissive mode permits prohibited category
    svc.policy_mut().unwrap().mode = ThreatPolicyMode::Permissive;
    let perm_entry = create_valid_entry(
        "THREAT-PERM-01",
        ThreatCategory::Repudiation,
        ThreatSeverity::Low,
        "CWE-284",
    );
    assert!(svc.register_threat(perm_entry).is_ok());
    assert_eq!(svc.list_threats().len(), 2);

    // 10. Persistence roundtrip with policy-enforced service
    let tmp = tempdir().expect("tempdir");
    let store_file = tmp.path().join("threats_policy_verified.json");
    assert!(svc.save_to_path(&store_file).is_ok());

    let loaded_svc = ThreatModelService::load_from_path(&store_file).expect("load success");
    assert_eq!(loaded_svc.list_threats().len(), 2);
    assert_eq!(
        loaded_svc.get_threat("THREAT-CRIT-99").unwrap().status,
        ThreatStatus::Resolved
    );
}
