//! Integration Tests for Incident Response Runbooks Data Model (T-02968).
//!
//! Tests JSON wire format compatibility, schema validation, and multi-step catalog interaction.

use aiosh_core::incident_runbook_data_model::*;

#[test]
fn test_integration_canonical_baseline_wire_format() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let json_str = baseline.to_json().expect("Serialization failed");

    let val: serde_json::Value = serde_json::from_str(&json_str).expect("Valid JSON expected");
    assert_eq!(val["version"], "1.0.0");
    assert!(val["generated_at"].is_string());
    assert!(val["runbooks"].is_array());
    assert_eq!(val["runbooks"].as_array().unwrap().len(), 2);

    let rb1 = &val["runbooks"][0];
    assert_eq!(rb1["id"], "RB-IR-MALWARE-01");
    assert_eq!(rb1["category"], "malware_containment");
    assert_eq!(rb1["severity"], "high");
    assert_eq!(rb1["steps"].as_array().unwrap().len(), 3);

    let step1 = &rb1["steps"][0];
    assert_eq!(step1["id"], "STEP-MW-01");
    assert_eq!(step1["target"], "process");
    assert_eq!(step1["phase"], "containment");
    assert_eq!(step1["automated"], true);
    assert_eq!(step1["requires_confirmation"], false);
    assert_eq!(step1["timeout_seconds"], 15);
}

#[test]
fn test_integration_custom_runbook_catalog_flow() {
    let mut catalog = RunbookCatalogSnapshot::new("2.0.0");

    let s1 = RunbookStep::new(
        "STEP-EXFIL-01",
        "Sever suspect egress sockets",
        RunbookPhase::Containment,
        RunbookTargetSubstrate::Network,
        "aiosh net cut --pid {exfil_pid}",
        true,
        false,
        10,
    ).unwrap();

    let s2 = RunbookStep::new(
        "STEP-EXFIL-02",
        "Archive exfiltration socket states for audit evidence",
        RunbookPhase::PostIncident,
        RunbookTargetSubstrate::AuditRing,
        "aiosh audit checkpoint --evidence {socket_state}",
        true,
        false,
        20,
    ).unwrap();

    let rb = RunbookSpec::new(
        "RB-EXFIL-01",
        "Data Exfiltration Rapid Severance",
        IncidentCategory::DataExfiltration,
        IncidentSeverity::Critical,
        "Terminates active unauthorized egress channels and snapshots states.",
        vec![s1, s2],
        vec!["exfil".to_string(), "network".to_string()],
    ).unwrap();

    assert!(catalog.add_runbook(rb).is_ok());
    assert_eq!(catalog.runbooks.len(), 1);

    // Cross-query integration
    let exfil_rbs = catalog.find_by_category(IncidentCategory::DataExfiltration);
    assert_eq!(exfil_rbs.len(), 1);
    assert_eq!(exfil_rbs[0].total_timeout_seconds(), 30);
    assert_eq!(exfil_rbs[0].steps_for_phase(RunbookPhase::Containment).len(), 1);
    assert_eq!(exfil_rbs[0].steps_for_phase(RunbookPhase::PostIncident).len(), 1);

    // Roundtrip verification
    let json = catalog.to_json().unwrap();
    let rehydrated = RunbookCatalogSnapshot::from_json(&json).unwrap();
    assert_eq!(rehydrated.version, "2.0.0");
    assert_eq!(rehydrated.runbooks.len(), 1);
    assert_eq!(rehydrated.runbooks[0].id, "RB-EXFIL-01");
}
