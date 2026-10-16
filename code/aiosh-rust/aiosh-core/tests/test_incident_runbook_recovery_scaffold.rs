//! Scaffold test for Incident Response Runbooks recovery & validation (T-03055).

use aiosh_core::incident_runbook_recovery::{
    RunbookCatalogStatus, RunbookIssueSeverity, RunbookIssueType, RunbookRecoveryReport,
    RunbookRecoveryResultEnvelope, RunbookRecoveryService, RunbookValidationIssue,
    RunbookValidationReport, IRREC_ERR_IO, IRREC_ERR_NO_BACKUP, IRREC_ERR_PARSE,
    IRREC_ERR_PATH_TRAVERSAL, IRREC_ERR_VALIDATION, MAX_QUARANTINE_FILES, MAX_RUNBOOK_STATE_SIZE,
};
use std::path::Path;

#[test]
fn test_recovery_scaffold_types_and_constants() {
    assert_eq!(IRREC_ERR_IO, "IRREC_ERR_IO");
    assert_eq!(IRREC_ERR_PARSE, "IRREC_ERR_PARSE");
    assert_eq!(IRREC_ERR_PATH_TRAVERSAL, "IRREC_ERR_PATH_TRAVERSAL");
    assert_eq!(IRREC_ERR_VALIDATION, "IRREC_ERR_VALIDATION");
    assert_eq!(IRREC_ERR_NO_BACKUP, "IRREC_ERR_NO_BACKUP");
    assert_eq!(MAX_RUNBOOK_STATE_SIZE, 10 * 1024 * 1024);
    assert_eq!(MAX_QUARANTINE_FILES, 10);

    let status = RunbookCatalogStatus::Healthy;
    assert_eq!(status, RunbookCatalogStatus::Healthy);

    let issue = RunbookValidationIssue {
        issue_type: RunbookIssueType::MissingStateFile,
        severity: RunbookIssueSeverity::Critical,
        message: "File missing".to_string(),
        target_id: None,
    };
    assert_eq!(issue.severity, RunbookIssueSeverity::Critical);

    let report = RunbookValidationReport {
        status: RunbookCatalogStatus::Missing,
        checked_at_utc: "2026-10-16T12:00:00Z".to_string(),
        target_path: "/tmp/state.json".to_string(),
        issues: vec![issue],
        total_runbooks: 0,
        total_active_sessions: 0,
        is_recoverable: true,
    };
    assert_eq!(report.status, RunbookCatalogStatus::Missing);

    let env = RunbookRecoveryResultEnvelope::success(report);
    assert!(env.ok);
    assert!(env.data.is_some());
    assert!(!env.audit_row_required);

    let rec_report = RunbookRecoveryReport {
        ok: true,
        recovered_at_utc: "2026-10-16T12:00:00Z".to_string(),
        quarantine_path: None,
        backup_path: None,
        restored_runbooks_count: 5,
        action_taken: "noop".to_string(),
    };
    assert!(rec_report.ok);
}

#[test]
fn test_recovery_implementation_basic_validation() {
    let p = Path::new("/dummy/nonexistent/runbook_state.json");
    let rep = RunbookRecoveryService::validate_state_path(p);
    assert_eq!(rep.status, RunbookCatalogStatus::Missing);
    assert!(!rep.issues.is_empty());
}
