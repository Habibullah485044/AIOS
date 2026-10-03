//! Integration Tests for Threat Model Core Service (T-02716).

use std::fs;
use aiosh_core::*;

#[test]
fn test_threat_model_service_end_to_end_integration() {
    let mut service = ThreatModelService::with_canonical_threats();
    assert_eq!(service.list_threats().len(), 7);

    // Initial risk assessment on canonical threats (all 7 canonical threats are mitigated baseline)
    let initial_assessment = service.assess_risk();
    assert_eq!(initial_assessment.total_threats, 7);
    assert_eq!(initial_assessment.mitigated_count, 7);
    assert_eq!(initial_assessment.identified_count, 0);
    assert_eq!(initial_assessment.critical_unmitigated_count, 0);

    // Register a new active unmitigated threat
    let new_threat = ThreatEntry::new(
        "THREAT-INT-099",
        "WASM Host Function Escape",
        "Escape through unbounded hostcall pointers in agent sandboxes",
        ThreatCategory::ElevationOfPrivilege,
        ThreatSeverity::Critical,
        "wasm_runtime",
        vec!["CWE-119".into()],
        vec![],
    ).expect("valid threat");

    service.register_threat(new_threat).expect("registered threat");
    assert_eq!(service.list_threats().len(), 8);

    let active_assessment = service.assess_risk();
    assert_eq!(active_assessment.identified_count, 1);
    assert_eq!(active_assessment.critical_unmitigated_count, 1);
    assert!(active_assessment.overall_risk_score > initial_assessment.overall_risk_score);

    // Progress the threat through the review and mitigation lifecycle
    let crit_id = "THREAT-INT-099";
    let step1 = service.update_status(crit_id, ThreatStatus::UnderReview);
    assert!(step1.is_ok());

    let step2 = service.attach_mitigation(
        crit_id,
        "Implement mandatory bounds checking and memory sandboxing for hostcalls.",
    );
    assert!(step2.is_ok());

    let step3 = service.update_status(crit_id, ThreatStatus::Mitigated);
    assert!(step3.is_ok());

    // Re-assess risk after mitigation
    let updated_assessment = service.assess_risk();
    assert_eq!(updated_assessment.identified_count, 0);
    assert_eq!(updated_assessment.mitigated_count, 8);
    assert_eq!(updated_assessment.critical_unmitigated_count, 0);

    // Test persistence round-trip
    let tmp_dir = std::env::temp_dir().join("test_threat_model_service_integration");
    let _ = fs::create_dir_all(&tmp_dir);
    let target_file = tmp_dir.join("threat_model_int.json");

    let save_res = service.save_to_path(&target_file);
    assert!(save_res.is_ok());
    assert!(target_file.exists());

    let loaded_service = ThreatModelService::load_from_path(&target_file).expect("loaded service");
    assert_eq!(loaded_service.list_threats().len(), 8);
    let re_crit = loaded_service.get_threat(crit_id).expect("retrieved mitigated threat");
    assert_eq!(re_crit.status, ThreatStatus::Mitigated);

    let _ = fs::remove_file(&target_file);
    let _ = fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_threat_model_service_capacity_and_error_handling() {
    let mut service = ThreatModelService::new();
    assert_eq!(service.list_threats().len(), 0);

    // Attempting to query nonexistent threat
    assert_eq!(service.get_threat("THREAT-NONEXISTENT"), None);
    let err = service.update_status("THREAT-NONEXISTENT", ThreatStatus::Mitigated).unwrap_err();
    assert!(err.starts_with(THREATSVC_ERR_NOT_FOUND));

    // Verify path traversal rejection
    let save_err = service.save_to_path(std::path::Path::new("../escaped.json")).unwrap_err();
    assert!(save_err.starts_with(THREATSVC_ERR_PATH_TRAVERSAL));

    let load_err = ThreatModelService::load_from_path(std::path::Path::new("foo/../../bar.json")).unwrap_err();
    assert!(load_err.starts_with(THREATSVC_ERR_PATH_TRAVERSAL));
}
