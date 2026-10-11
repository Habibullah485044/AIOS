//! Implementation Smoke Test for Compliance Mapping Observability (T-02936).

use aiosh_core::compliance_observability::{
    sanitize_telemetry_text, ComplianceObservabilityReport,
    COMPOBS_ERR_SERVICE_INACCESSIBLE, COMPOBS_ERR_VALIDATION,
};
use aiosh_core::compliance_service::ComplianceService;

#[test]
fn test_observability_implementation_smoke() {
    assert_eq!(COMPOBS_ERR_VALIDATION, "COMPOBS_ERR_VALIDATION");
    assert_eq!(COMPOBS_ERR_SERVICE_INACCESSIBLE, "COMPOBS_ERR_SERVICE_INACCESSIBLE");
    assert_eq!(sanitize_telemetry_text("hello\x00world"), "helloworld");

    let svc = ComplianceService::with_canonical_baseline();
    let res = ComplianceObservabilityReport::generate(&svc, None);
    assert!(res.is_ok());
    let report = res.unwrap();
    assert_eq!(report.total_mappings, svc.snapshot.mappings.len());
    assert!(report.is_healthy);
    assert!(report.mappings_by_framework.contains_key("nist_sp_800_53_rev5"));
    assert_eq!(report.policy_mode, "unconfigured");
    assert!(report.validate().is_ok());

    let via_svc = svc.observability_report(None).expect("observability report from service");
    assert_eq!(via_svc.total_mappings, report.total_mappings);
}
