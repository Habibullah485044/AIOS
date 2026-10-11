//! Scaffold verification tests for Compliance Mapping Recovery & Validation (T-02955).

use std::path::Path;
use aiosh_core::compliance_recovery::{
    ComplianceCatalogStatus, ComplianceIssueSeverity, ComplianceIssueType,
    ComplianceRecoveryService, COMPLYREC_ERR_FILE_SIZE, COMPLYREC_ERR_IO,
    COMPLYREC_ERR_NO_BACKUP, COMPLYREC_ERR_PARSE, COMPLYREC_ERR_PATH_TRAVERSAL,
    COMPLYREC_ERR_VALIDATION,
};

#[test]
fn test_compliance_recovery_scaffold_constants_and_types() {
    assert_eq!(COMPLYREC_ERR_IO, "COMPLYREC_ERR_IO");
    assert_eq!(COMPLYREC_ERR_PARSE, "COMPLYREC_ERR_PARSE");
    assert_eq!(COMPLYREC_ERR_PATH_TRAVERSAL, "COMPLYREC_ERR_PATH_TRAVERSAL");
    assert_eq!(COMPLYREC_ERR_FILE_SIZE, "COMPLYREC_ERR_FILE_SIZE");
    assert_eq!(COMPLYREC_ERR_VALIDATION, "COMPLYREC_ERR_VALIDATION");
    assert_eq!(COMPLYREC_ERR_NO_BACKUP, "COMPLYREC_ERR_NO_BACKUP");

    assert_eq!(ComplianceCatalogStatus::Healthy, ComplianceCatalogStatus::Healthy);
    assert_eq!(ComplianceIssueSeverity::Critical, ComplianceIssueSeverity::Critical);
    assert_eq!(ComplianceIssueType::SchemaMismatch, ComplianceIssueType::SchemaMismatch);
}

#[test]
fn test_compliance_recovery_scaffold_loud_failure_stubs() {
    let dummy_path = Path::new("dummy/path.json");

    let val_res = ComplianceRecoveryService::validate_path(dummy_path);
    assert!(val_res.is_err());
    assert!(val_res.unwrap_err().contains("not implemented"));

    let backup_res = ComplianceRecoveryService::create_backup(dummy_path);
    assert!(backup_res.is_err());
    assert!(backup_res.unwrap_err().contains("not implemented"));

    let repair_res = ComplianceRecoveryService::repair_catalog(dummy_path);
    assert!(repair_res.is_err());
    assert!(repair_res.unwrap_err().contains("not implemented"));

    let restore_res = ComplianceRecoveryService::restore_from_backup(dummy_path);
    assert!(restore_res.is_err());
    assert!(restore_res.unwrap_err().contains("not implemented"));
}
