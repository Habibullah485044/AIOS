//! Integration tests for RustSec security scanning and Incident Response runbooks (T-02988).

use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_service::*;
use aiosh_core::sec_tools::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_integration_runbook_and_forensic_scan_pipeline() {
    // 1. Set up simulated compromised environment with forensic log
    let dir = tempdir().unwrap();
    let auth_log = dir.path().join("audit_incident.log");
    let mut f = File::create(&auth_log).unwrap();
    writeln!(f, "2026-10-12T14:00:00Z auth: accepted pubkey for deploy").unwrap();
    writeln!(f, "2026-10-12T14:05:00Z detect: MALWARE_IOC_HASH_DETECTED pid=9876 uid=1001").unwrap();
    writeln!(f, "2026-10-12T14:05:01Z network: outbound socket 9876 -> 192.168.1.50:4444").unwrap();

    // 2. Perform forensic log scanning with RustSec scan_files
    let scan_res = scan_files(dir.path().to_str().unwrap(), "MALWARE_IOC_HASH_DETECTED", 2, 5, None).unwrap();
    assert_eq!(scan_res.matches.len(), 1);
    assert_eq!(scan_res.matches[0].line_number, 2);
    assert!(scan_res.matches[0].line_content.contains("pid=9876"));

    // 3. Match and instantiate Incident Response Runbook
    let catalog = RunbookCatalogSnapshot::canonical_baseline();
    let spec = match_runbook(&catalog, IncidentCategory::MalwareContainment, IncidentSeverity::High).unwrap();
    assert_eq!(spec.id, "RB-IR-MALWARE-01");

    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "9876".to_string());
    params.insert("target_uid".to_string(), "1001".to_string());

    let mut session = RunbookExecutionSession::init_from_spec(spec, "INC-2026-AUTOSCAN", params).unwrap();
    assert_eq!(session.status, RunbookExecutionStatus::Pending);

    // 4. Advance containment steps
    let st1 = session.advance_step(spec, true).unwrap();
    assert_eq!(st1, StepExecutionStatus::Completed);
    assert_eq!(session.step_records[0].command_rendered, "aiosh run kill -STOP 9876");

    let st2 = session.advance_step(spec, true).unwrap();
    assert_eq!(st2, StepExecutionStatus::Completed);
    assert_eq!(session.step_records[1].command_rendered, "aiosh run iptables -A OUTPUT -m owner --uid-owner 1001 -j DROP");

    let st3 = session.advance_step(spec, true).unwrap();
    assert_eq!(st3, StepExecutionStatus::Completed);
    assert_eq!(session.step_records[2].command_rendered, "aiosh audit checkpoint --reason 'Malware containment forensic snapshot'");
    assert_eq!(session.status, RunbookExecutionStatus::Completed);

    // 5. Verify local network perimeter with scan_net
    let net_res = scan_net("127.0.0.1", &[65530, 65531], 2, None).unwrap();
    assert_eq!(net_res.target, "127.0.0.1");
    assert_eq!(net_res.scanned_ports_count, 2);

    // 6. JSON roundtrip & rehydration
    let json_dump = session.to_json().unwrap();
    let restored = RunbookExecutionSession::from_json(&json_dump).unwrap();
    assert_eq!(restored.session_id, session.session_id);
    assert_eq!(restored.status, RunbookExecutionStatus::Completed);
    assert_eq!(restored.step_records.len(), 3);
}
