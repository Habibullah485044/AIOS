"""Scaffold test for MCP Server Core Automated Tests (T-03115)."""

import pytest
from aiosh_mcp.mcp_server_core_tests import (
    McpTestCategory,
    McpTestCase,
    McpTestSuiteReport,
    run_all_mcp_tests,
    run_category_tests,
)


def test_mcp_tests_scaffold_types():
    tc = McpTestCase(
        test_id="TEST-01",
        category=McpTestCategory.DATA_MODEL,
        name="test-name",
        passed=True,
        duration_ms=1.5,
    )
    d = tc.to_dict()
    assert d["test_id"] == "TEST-01"
    assert d["passed"] is True

    rep = McpTestSuiteReport(
        suite_name="test_suite",
        total_cases=1,
        passed_cases=1,
        failed_cases=0,
        duration_seconds=0.05,
        cases=[tc],
    )
    assert rep.success is True
    md = rep.to_markdown()
    assert "TEST-01" in md


def test_mcp_tests_scaffold_functions_fail_loudly():
    with pytest.raises(NotImplementedError):
        run_all_mcp_tests()

    with pytest.raises(NotImplementedError):
        run_category_tests("data_model")
