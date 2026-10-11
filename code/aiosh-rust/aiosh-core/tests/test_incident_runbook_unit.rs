//! Comprehensive Unit Tests for Incident Response Runbooks Data Model (T-02967).
//!
//! Covers invariants IR-INV1..IR-INV5, validation bounds, enum conversions,
//! querying, filtering, capacity management, and JSON roundtrip serialization.

use aiosh_core::incident_runbook_data_model::*;

#[test]
fn test_severity_parsing_and_display() {
    assert_eq!(IncidentSeverity::parse_severity("low"), Some(IncidentSeverity::Low));
    assert_eq!(IncidentSeverity::parse_severity("medium"), Some(IncidentSeverity::Medium));
    assert_eq!(IncidentSeverity::parse_severity("med"), Some(IncidentSeverity::Medium));
    assert_eq!(IncidentSeverity::parse_severity("high"), Some(IncidentSeverity::High));
    assert_eq!(IncidentSeverity::parse_severity("critical"), Some(IncidentSeverity::Critical));
    assert_eq!(IncidentSeverity::parse_severity("crit"), Some(IncidentSeverity::Critical));
    assert_eq!(IncidentSeverity::parse_severity("unknown"), None);

    assert_eq!(IncidentSeverity::Low.as_str(), "low");
    assert_eq!(format!("{}", IncidentSeverity::Critical), "critical");
}

#[test]
fn test_category_parsing_and_display() {
    assert_eq!(IncidentCategory::parse_category("malware_containment"), Some(IncidentCategory::MalwareContainment));
    assert_eq!(IncidentCategory::parse_category("malware"), Some(IncidentCategory::MalwareContainment));
    assert_eq!(IncidentCategory::parse_category("unauthorized_access"), Some(IncidentCategory::UnauthorizedAccess));
    assert_eq!(IncidentCategory::parse_category("access"), Some(IncidentCategory::UnauthorizedAccess));
    assert_eq!(IncidentCategory::parse_category("data_exfiltration"), Some(IncidentCategory::DataExfiltration));
    assert_eq!(IncidentCategory::parse_category("denial_of_service"), Some(IncidentCategory::DenialOfService));
    assert_eq!(IncidentCategory::parse_category("integrity_violation"), Some(IncidentCategory::IntegrityViolation));
    assert_eq!(IncidentCategory::parse_category("policy_bypass_attempt"), Some(IncidentCategory::PolicyBypassAttempt));
    assert_eq!(IncidentCategory::parse_category("invalid"), None);

    assert_eq!(IncidentCategory::MalwareContainment.as_str(), "malware_containment");
    assert_eq!(format!("{}", IncidentCategory::IntegrityViolation), "integrity_violation");
}

#[test]
fn test_phase_parsing_and_display() {
    assert_eq!(RunbookPhase::parse_phase("preparation"), Some(RunbookPhase::Preparation));
    assert_eq!(RunbookPhase::parse_phase("prep"), Some(RunbookPhase::Preparation));
    assert_eq!(RunbookPhase::parse_phase("detection"), Some(RunbookPhase::Detection));
    assert_eq!(RunbookPhase::parse_phase("containment"), Some(RunbookPhase::Containment));
    assert_eq!(RunbookPhase::parse_phase("eradication"), Some(RunbookPhase::Eradication));
    assert_eq!(RunbookPhase::parse_phase("recovery"), Some(RunbookPhase::Recovery));
    assert_eq!(RunbookPhase::parse_phase("post_incident"), Some(RunbookPhase::PostIncident));
    assert_eq!(RunbookPhase::parse_phase("invalid"), None);

    assert_eq!(RunbookPhase::Preparation.as_str(), "preparation");
    assert_eq!(format!("{}", RunbookPhase::Recovery), "recovery");
}

#[test]
fn test_target_substrate_parsing_and_display() {
    assert_eq!(RunbookTargetSubstrate::parse_target("process"), Some(RunbookTargetSubstrate::Process));
    assert_eq!(RunbookTargetSubstrate::parse_target("proc"), Some(RunbookTargetSubstrate::Process));
    assert_eq!(RunbookTargetSubstrate::parse_target("network"), Some(RunbookTargetSubstrate::Network));
    assert_eq!(RunbookTargetSubstrate::parse_target("identity"), Some(RunbookTargetSubstrate::Identity));
    assert_eq!(RunbookTargetSubstrate::parse_target("audit_ring"), Some(RunbookTargetSubstrate::AuditRing));
    assert_eq!(RunbookTargetSubstrate::parse_target("storage"), Some(RunbookTargetSubstrate::Storage));
    assert_eq!(RunbookTargetSubstrate::parse_target("invalid"), None);

    assert_eq!(RunbookTargetSubstrate::Process.as_str(), "process");
    assert_eq!(format!("{}", RunbookTargetSubstrate::AuditRing), "audit_ring");
}

#[test]
fn test_ir_inv1_identifier_validation() {
    assert!(validate_identifier("VALID_ID-01.test", "id").is_ok());
    assert!(validate_identifier("", "id").is_err());
    assert!(validate_identifier("   ", "id").is_err());
    assert!(validate_identifier(&"A".repeat(65), "id").is_err());
    assert!(validate_identifier("invalid@char", "id").is_err());
    assert!(validate_identifier("has space", "id").is_err());
}

#[test]
fn test_ir_inv2_control_character_rejection() {
    assert!(validate_title("Valid Title 123", "title").is_ok());
    assert!(validate_title("Title with \x00 null byte", "title").is_err());
    assert!(validate_title("Title with \x1b escape code", "title").is_err());
    assert!(validate_text_length("Valid description\nwith newline", 2048, "desc").is_ok());
    assert!(validate_text_length("Desc with \x07 bell", 2048, "desc").is_err());
}

#[test]
fn test_ir_inv3_and_inv4_runbook_validation_bounds() {
    let valid_step = RunbookStep::new(
        "STEP-1",
        "Step 1",
        RunbookPhase::Containment,
        RunbookTargetSubstrate::Process,
        "echo contain",
        true,
        false,
        15,
    ).unwrap();

    // Empty steps rejected (IR-INV4)
    let empty_steps_res = RunbookSpec::new(
        "RB-01",
        "Test RB",
        IncidentCategory::MalwareContainment,
        IncidentSeverity::High,
        "Desc",
        vec![],
        vec!["tag".to_string()],
    );
    assert!(empty_steps_res.is_err());
    assert!(empty_steps_res.unwrap_err().contains(RUNBOOK_ERR_EMPTY_STEPS));

    // Duplicate step IDs rejected
    let step_dup1 = valid_step.clone();
    let mut step_dup2 = valid_step.clone();
    step_dup2.title = "Step 2 with same ID".to_string();
    let dup_steps_res = RunbookSpec::new(
        "RB-01",
        "Test RB",
        IncidentCategory::MalwareContainment,
        IncidentSeverity::High,
        "Desc",
        vec![step_dup1, step_dup2],
        vec!["tag".to_string()],
    );
    assert!(dup_steps_res.is_err());
    assert!(dup_steps_res.unwrap_err().contains(RUNBOOK_ERR_DUPLICATE_ID));

    // Exceed max steps count (IR-INV3: > 32)
    let many_steps: Vec<RunbookStep> = (0..33)
        .map(|i| {
            RunbookStep::new(
                &format!("STEP-{:02}", i),
                &format!("Step {}", i),
                RunbookPhase::Containment,
                RunbookTargetSubstrate::Process,
                "cmd",
                true,
                false,
                10,
            ).unwrap()
        })
        .collect();
    let too_many_steps_res = RunbookSpec::new(
        "RB-01",
        "Test RB",
        IncidentCategory::MalwareContainment,
        IncidentSeverity::High,
        "Desc",
        many_steps,
        vec![],
    );
    assert!(too_many_steps_res.is_err());
    assert!(too_many_steps_res.unwrap_err().contains(RUNBOOK_ERR_BOUNDS_EXCEEDED));

    // Exceed max tags (IR-INV3: > 16)
    let many_tags: Vec<String> = (0..17).map(|i| format!("tag{}", i)).collect();
    let too_many_tags_res = RunbookSpec::new(
        "RB-01",
        "Test RB",
        IncidentCategory::MalwareContainment,
        IncidentSeverity::High,
        "Desc",
        vec![valid_step],
        many_tags,
    );
    assert!(too_many_tags_res.is_err());
    assert!(too_many_tags_res.unwrap_err().contains(RUNBOOK_ERR_BOUNDS_EXCEEDED));
}

#[test]
fn test_runbook_spec_query_methods() {
    let s1 = RunbookStep::new(
        "S1",
        "Step 1",
        RunbookPhase::Containment,
        RunbookTargetSubstrate::Process,
        "cmd1",
        true,
        false,
        10,
    ).unwrap();
    let s2 = RunbookStep::new(
        "S2",
        "Step 2",
        RunbookPhase::Containment,
        RunbookTargetSubstrate::Network,
        "cmd2",
        false,
        true,
        20,
    ).unwrap();
    let s3 = RunbookStep::new(
        "S3",
        "Step 3",
        RunbookPhase::PostIncident,
        RunbookTargetSubstrate::AuditRing,
        "cmd3",
        true,
        false,
        30,
    ).unwrap();

    let rb = RunbookSpec::new(
        "RB-QUERY-01",
        "Query Test",
        IncidentCategory::MalwareContainment,
        IncidentSeverity::Medium,
        "Query test description",
        vec![s1, s2, s3],
        vec!["test".to_string(), "query".to_string()],
    ).unwrap();

    assert_eq!(rb.steps_for_phase(RunbookPhase::Containment).len(), 2);
    assert_eq!(rb.steps_for_phase(RunbookPhase::PostIncident).len(), 1);
    assert_eq!(rb.steps_for_phase(RunbookPhase::Eradication).len(), 0);

    assert_eq!(rb.steps_for_target(RunbookTargetSubstrate::Process).len(), 1);
    assert_eq!(rb.steps_for_target(RunbookTargetSubstrate::Network).len(), 1);
    assert_eq!(rb.steps_for_target(RunbookTargetSubstrate::Storage).len(), 0);

    assert_eq!(rb.automated_steps().len(), 2);
    assert_eq!(rb.manual_steps().len(), 1);
    assert_eq!(rb.total_timeout_seconds(), 60);
    assert!(rb.validate().is_ok());
}

#[test]
fn test_catalog_snapshot_operations_and_filters() {
    let mut catalog = RunbookCatalogSnapshot::canonical_baseline();
    assert_eq!(catalog.runbooks.len(), 2);

    // Filter by category
    let mw = catalog.find_by_category(IncidentCategory::MalwareContainment);
    assert_eq!(mw.len(), 1);
    assert_eq!(mw[0].id, "RB-IR-MALWARE-01");

    // Filter by severity
    let crit = catalog.find_by_severity(IncidentSeverity::Critical);
    assert_eq!(crit.len(), 1);
    assert_eq!(crit[0].id, "RB-IR-ACCESS-01");

    // Filter by phase
    let post = catalog.filter_by_phase(RunbookPhase::PostIncident);
    assert_eq!(post.len(), 1);

    // Filter by target
    let net = catalog.filter_by_target(RunbookTargetSubstrate::Network);
    assert_eq!(net.len(), 1);

    // Filter by tag
    let tagged = catalog.filter_by_tag("emergency");
    assert_eq!(tagged.len(), 1);

    // Add duplicate ID rejected
    let dup_rb = catalog.runbooks[0].clone();
    assert!(catalog.add_runbook(dup_rb).is_err());

    // Get runbook
    assert!(catalog.get_runbook("RB-IR-MALWARE-01").is_some());
    assert!(catalog.get_runbook("NON-EXISTENT").is_none());

    // Remove runbook
    let removed = catalog.remove_runbook("RB-IR-MALWARE-01");
    assert!(removed.is_some());
    assert_eq!(catalog.runbooks.len(), 1);
    assert!(catalog.get_runbook("RB-IR-MALWARE-01").is_none());
}

#[test]
fn test_json_roundtrip_serialization() {
    let baseline = RunbookCatalogSnapshot::canonical_baseline();
    let json_str = baseline.to_json().expect("Serialization must succeed");
    assert!(!json_str.is_empty());

    let deserialized = RunbookCatalogSnapshot::from_json(&json_str).expect("Deserialization must succeed");
    assert_eq!(baseline.version, deserialized.version);
    assert_eq!(baseline.runbooks.len(), deserialized.runbooks.len());
    assert_eq!(baseline.runbooks[0].id, deserialized.runbooks[0].id);
    assert_eq!(baseline.runbooks[0].steps.len(), deserialized.runbooks[0].steps.len());
}
