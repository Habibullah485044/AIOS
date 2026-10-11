//! Scaffold Smoke Tests for Incident Response Runbooks Data Model (T-02965).

use aiosh_core::incident_runbook_data_model::*;

#[test]
fn test_incident_runbook_scaffold_types() {
    assert_eq!(IncidentSeverity::Low.as_str(), "low");
    assert_eq!(IncidentSeverity::Critical.as_str(), "critical");
    assert_eq!(IncidentSeverity::parse_severity("high"), Some(IncidentSeverity::High));

    assert_eq!(IncidentCategory::MalwareContainment.as_str(), "malware_containment");
    assert_eq!(IncidentCategory::UnauthorizedAccess.as_str(), "unauthorized_access");

    assert_eq!(RunbookPhase::Containment.as_str(), "containment");
    assert_eq!(RunbookTargetSubstrate::Process.as_str(), "process");
}

#[test]
fn test_incident_runbook_canonical_baseline_scaffold() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    assert_eq!(baseline.version, "1.0.0");
    assert_eq!(baseline.runbooks.len(), 2);

    let malware_rb = baseline.get_runbook("RB-IR-MALWARE-01").expect("malware runbook");
    assert_eq!(malware_rb.severity, IncidentSeverity::High);
    assert_eq!(malware_rb.steps.len(), 3);

    let access_rb = baseline.get_runbook("RB-IR-ACCESS-01").expect("access runbook");
    assert_eq!(access_rb.severity, IncidentSeverity::Critical);
    assert_eq!(access_rb.steps.len(), 2);
}
