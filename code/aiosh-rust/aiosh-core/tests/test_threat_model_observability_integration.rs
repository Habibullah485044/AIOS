//! Integration Tests for Threat Model Observability (T-02776).

use tempfile::tempdir;

use aiosh_core::audit::{AuditRing, AuditRowInput};
use aiosh_core::threat_model_observability::ThreatModelObservabilityReport;
use aiosh_core::threat_model_policy::ThreatModelSecurityPolicy;
use aiosh_core::threat_model_service::ThreatModelService;

#[test]
fn test_threat_observability_end_to_end_integration() {
    let tmp = tempdir().expect("tempdir");
    let store_path = tmp.path().join("threats_observability_integrated.json");

    // 1. Initialize service with canonical STRIDE threats and attach security policy
    let mut service = ThreatModelService::with_canonical_threats();
    let policy = ThreatModelSecurityPolicy::default();
    service.set_policy(policy);

    assert_eq!(service.list_threats().len(), 7);

    // 2. Open an in-memory AuditRing and record threat and non-threat events
    let mut ring = AuditRing::open_in_memory().expect("open audit ring");

    let mut row_threat1 = AuditRowInput::default();
    row_threat1.actor = "security_agent".into();
    row_threat1.tool = "aios.threat.register".into();
    row_threat1.command = "threat register".into();
    ring.write(row_threat1).expect("write row 1");

    let mut row_threat2 = AuditRowInput::default();
    row_threat2.actor = "security_agent".into();
    row_threat2.tool = "aios.threat.status".into();
    row_threat2.command = "threat update_status".into();
    ring.write(row_threat2).expect("write row 2");

    let mut row_unrelated = AuditRowInput::default();
    row_unrelated.actor = "worker".into();
    row_unrelated.tool = "aios.secret.store".into();
    row_unrelated.command = "secret store".into();
    ring.write(row_unrelated).expect("write row 3");

    // 3. Persist threat catalog to disk and reload in a fresh service instance
    service.save_to_path(&store_path).expect("save succeeded");
    let mut loaded_service = ThreatModelService::load_from_path(&store_path).expect("load succeeded");
    loaded_service.set_policy(ThreatModelSecurityPolicy::default());

    // 4. Generate report with audit correlation
    let report = ThreatModelObservabilityReport::generate(&loaded_service, Some(&ring))
        .expect("report generation succeeds");

    assert_eq!(report.total_threats, 7);
    assert_eq!(report.policy_mode, "enforcing");
    assert!(report.is_healthy);
    assert_eq!(report.recent_audit_events_count, 2);

    // Verify category distribution includes all 6 STRIDE categories plus supply chain risk
    assert_eq!(report.threats_by_category.len(), 7);
    assert_eq!(report.threats_by_category.get("spoofing"), Some(&1));
    assert_eq!(report.threats_by_category.get("tampering"), Some(&1));
    assert_eq!(report.threats_by_category.get("repudiation"), Some(&1));
    assert_eq!(report.threats_by_category.get("information_disclosure"), Some(&1));
    assert_eq!(report.threats_by_category.get("denial_of_service"), Some(&1));
    assert_eq!(report.threats_by_category.get("elevation_of_privilege"), Some(&1));
    assert_eq!(report.threats_by_category.get("supply_chain_risk"), Some(&1));

    // 5. JSON serialization and schema integrity
    let json_output = report.to_json().expect("to_json succeeds");
    let parsed_back = ThreatModelObservabilityReport::from_json(&json_output).expect("from_json succeeds");
    assert_eq!(report, parsed_back);

    // Zero-disclosure invariant on telemetry: no internal passwords or keys
    assert!(!json_output.contains("BEGIN RSA PRIVATE KEY"));
}
