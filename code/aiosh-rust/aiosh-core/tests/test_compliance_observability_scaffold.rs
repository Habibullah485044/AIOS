//! Scaffold Stub Test for Compliance Mapping Observability (T-02935).

use aiosh_core::compliance_observability::{
    sanitize_telemetry_text, ComplianceObservabilityReport,
    COMPOBS_ERR_SERVICE_INACCESSIBLE, COMPOBS_ERR_VALIDATION,
};
use aiosh_core::compliance_service::ComplianceService;

#[test]
fn test_scaffold_symbols_and_loud_fail() {
    assert_eq!(COMPOBS_ERR_VALIDATION, "COMPOBS_ERR_VALIDATION");
    assert_eq!(COMPOBS_ERR_SERVICE_INACCESSIBLE, "COMPOBS_ERR_SERVICE_INACCESSIBLE");
    assert_eq!(sanitize_telemetry_text("hello\x00world"), "helloworld");

    let svc = ComplianceService::new();
    let res = ComplianceObservabilityReport::generate(&svc, None);
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("not implemented"));
}
