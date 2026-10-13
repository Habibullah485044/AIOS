//! Integration tests for Runbook configuration and Incident Runbook Service (T-03008).

use aiosh_core::incident_runbook_data_model::*;
use aiosh_core::incident_runbook_service::*;
use aiosh_core::runbook_config::*;
use std::collections::HashMap;

#[test]
fn test_integration_runbook_service_respects_config_defaults() {
    let cfg = resolve_runbook_config(None).expect("resolve default config");

    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let spec = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();
    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "4096".to_string());
    params.insert("target_uid".to_string(), "1001".to_string());

    let session = RunbookExecutionSession::init_from_spec(spec, "INC-2026-INT-01", params)
        .expect("init session");

    // Default configuration expects confirmation by default
    assert!(cfg.require_operator_confirmation);

    // Verify session initializes in Pending status
    assert_eq!(session.status, RunbookExecutionStatus::Pending);
    assert_eq!(session.current_step_index, 0);
    assert_eq!(session.step_records.len(), 3);
}

#[test]
fn test_integration_custom_overrides_applied_to_service_workflow() {
    let overrides = RunbookConfigOverrides {
        config_path: None,
        catalog_path: Some("docs/custom_catalog.json".to_string()),
        max_active_sessions: Some(50),
        max_catalog_file_bytes: Some(512 * 1024),
        default_step_timeout_seconds: Some(120),
        require_operator_confirmation: Some(false),
    };

    let cfg = resolve_runbook_config(Some(&overrides)).expect("resolve overrides");
    assert_eq!(cfg.max_active_sessions, 50);
    assert_eq!(cfg.default_step_timeout_seconds, 120);
    assert!(!cfg.require_operator_confirmation);
    assert_eq!(cfg.sources.get("max_active_sessions"), Some(&ConfigSource::Argument));

    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let spec = baseline.get_runbook("RB-IR-MALWARE-01").unwrap();
    let mut params = HashMap::new();
    params.insert("target_pid".to_string(), "4096".to_string());
    params.insert("target_uid".to_string(), "1001".to_string());

    let mut session = RunbookExecutionSession::init_from_spec(spec, "INC-2026-INT-02", params)
        .expect("init session");

    // Advance step 1
    let s1 = session.advance_step(spec, true).expect("advance step 1");
    assert_eq!(s1, StepExecutionStatus::Completed);
    assert_eq!(session.current_step_index, 1);
}
