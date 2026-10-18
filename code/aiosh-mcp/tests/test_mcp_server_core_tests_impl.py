"""Implementation test for MCP Server Core Automated Tests (T-03116)."""

import pytest
from aiosh_mcp.mcp_server_core_tests import (
    run_all_mcp_tests,
    run_category_tests,
    McpTestCategory,
)


def test_mcp_run_all_tests():
    report = run_all_mcp_tests()
    assert report.total_cases >= 10
    assert report.passed_cases == report.total_cases
    assert report.failed_cases == 0
    assert report.success is True
    assert report.duration_seconds >= 0.0

    d = report.to_dict()
    assert d["success"] is True
    assert len(d["cases"]) == report.total_cases

    md = report.to_markdown()
    assert "# MCP Server Core Test Suite Report" in md
    assert "PASS" in md


@pytest.mark.parametrize("category", ["data_model", "api", "service", "config", "security"])
def test_mcp_run_category_tests(category):
    report = run_category_tests(category)
    assert report.total_cases > 0
    assert report.passed_cases == report.total_cases
    assert report.failed_cases == 0
    assert report.success is True
