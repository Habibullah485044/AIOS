"""Scaffold tests for Incident Response Runbooks recovery & validation (T-03055)."""

import pytest

from aiosh_mcp.incident_runbook_recovery import (
    RunbookCatalogStatus,
    RunbookIssueSeverity,
    RunbookIssueType,
    RunbookRecoveryReport,
    RunbookRecoveryResultEnvelope,
    RunbookRecoveryService,
    RunbookValidationIssue,
    RunbookValidationReport,
    IRREC_ERR_IO,
    IRREC_ERR_NO_BACKUP,
    IRREC_ERR_PARSE,
    IRREC_ERR_PATH_TRAVERSAL,
    IRREC_ERR_VALIDATION,
    MAX_QUARANTINE_FILES,
    MAX_RUNBOOK_STATE_SIZE,
)


def test_recovery_scaffold_types_and_constants():
    assert IRREC_ERR_IO == "IRREC_ERR_IO"
    assert IRREC_ERR_PARSE == "IRREC_ERR_PARSE"
    assert IRREC_ERR_PATH_TRAVERSAL == "IRREC_ERR_PATH_TRAVERSAL"
    assert IRREC_ERR_VALIDATION == "IRREC_ERR_VALIDATION"
    assert IRREC_ERR_NO_BACKUP == "IRREC_ERR_NO_BACKUP"
    assert MAX_RUNBOOK_STATE_SIZE == 10 * 1024 * 1024
    assert MAX_QUARANTINE_FILES == 10

    issue = RunbookValidationIssue(
        issue_type=RunbookIssueType.MISSING_STATE_FILE,
        severity=RunbookIssueSeverity.CRITICAL,
        message="State file missing",
    )
    report = RunbookValidationReport(
        status=RunbookCatalogStatus.MISSING,
        checked_at_utc="2026-10-16T12:00:00Z",
        target_path="/tmp/state.json",
        issues=[issue],
        is_recoverable=True,
    )
    d = report.to_dict()
    assert d["status"] == "missing"
    assert len(d["issues"]) == 1

    env = RunbookRecoveryResultEnvelope.success(report)
    assert env.ok is True
    assert env.data == report
    assert env.audit_row_required is False


def test_recovery_implementation_basic_validation():
    rep = RunbookRecoveryService.validate_state_path("/dummy/nonexistent/state.json")
    assert rep.status == RunbookCatalogStatus.MISSING
    assert len(rep.issues) > 0
