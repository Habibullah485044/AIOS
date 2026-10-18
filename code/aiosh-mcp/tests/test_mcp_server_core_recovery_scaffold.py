"""Unit tests for MCP Server Core Recovery & Validation scaffold (T-03155)."""

import pytest
from pathlib import Path
from aiosh_mcp.mcp_server_core_recovery import (
    McpValidationIssue,
    McpValidationReport,
    McpRecoveryResult,
    validate_store_path,
    validate_mcp_store,
)


def test_recovery_scaffold_types():
    issue = McpValidationIssue(
        severity="ERROR",
        code="TEST_CODE",
        message="Test issue message",
        path="/tmp/store.json",
    )
    assert issue.code == "TEST_CODE"
    assert issue.to_dict()["severity"] == "ERROR"

    report = McpValidationReport(
        store_path="/tmp/store.json",
        is_healthy=True,
        total_records=2,
        valid_records=2,
        invalid_records=0,
        issues=[],
    )
    report.validate_invariants()
    assert report.is_healthy is True
    assert report.to_dict()["total_records"] == 2

    res = McpRecoveryResult(
        ok=True,
        action_taken="NONE",
        backup_path=None,
        report=report,
    )
    assert res.ok is True
    assert res.to_dict()["action_taken"] == "NONE"


def test_recovery_scaffold_path_validation():
    p = validate_store_path(".aios/store.json")
    assert isinstance(p, Path)

    with pytest.raises(ValueError):
        validate_store_path("../traversal/escape.json")
    with pytest.raises(ValueError):
        validate_store_path("")
    with pytest.raises(ValueError):
        validate_store_path("store\0null.json")
