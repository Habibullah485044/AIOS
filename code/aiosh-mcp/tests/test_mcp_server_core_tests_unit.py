"""Unit tests for MCP Server Core Automated Tests Subsystem (T-03117).

Covers 4-case test battery:
Case 1: Valid execution and report serialization across categories.
Case 2: Invalid category rejection.
Case 3: Boundary values for success computation and durations.
Case 4: Primary failure modes: graceful error capture and reporting.
"""

import pytest
from aiosh_mcp.mcp_server_core_tests import (
    McpTestCategory,
    McpTestCase,
    McpTestSuiteReport,
    run_all_mcp_tests,
    run_category_tests,
    _execute_test,
)


def test_unit_case1_valid_execution_and_reports():
    # Run full suite
    rep = run_all_mcp_tests()
    assert rep.total_cases >= 10
    assert rep.passed_cases == rep.total_cases
    assert rep.failed_cases == 0
    assert rep.success is True
    assert rep.duration_seconds >= 0.0

    # Serialization
    d = rep.to_dict()
    assert d["suite_name"] == "mcp_server_core_automated_tests"
    assert d["success"] is True
    assert len(d["cases"]) == rep.total_cases

    md = rep.to_markdown()
    assert "# MCP Server Core Test Suite Report" in md
    assert "PASS" in md

    # Individual valid categories
    for cat in ("data_model", "api", "service", "config", "security"):
        c_rep = run_category_tests(cat)
        assert c_rep.total_cases > 0
        assert c_rep.passed_cases == c_rep.total_cases
        assert c_rep.failed_cases == 0
        assert c_rep.success is True


def test_unit_case2_invalid_inputs():
    with pytest.raises(ValueError) as exc1:
        run_category_tests("unknown_cat")
    assert "Unknown category" in str(exc1.value)

    with pytest.raises(ValueError) as exc2:
        run_category_tests("")
    assert "Unknown category" in str(exc2.value)


def test_unit_case3_boundary_values():
    # Empty report boundary: 0 total cases must yield success == False
    empty_rep = McpTestSuiteReport(total_cases=0, passed_cases=0, failed_cases=0)
    assert empty_rep.success is False

    # 1 failure out of many: success == False
    failed_rep = McpTestSuiteReport(total_cases=10, passed_cases=9, failed_cases=1)
    assert failed_rep.success is False

    # Exactly 1 case passed: success == True
    single_pass = McpTestSuiteReport(total_cases=1, passed_cases=1, failed_cases=0)
    assert single_pass.success is True


def test_unit_case4_primary_failure_modes():
    # Test function raising AssertionError
    def failing_fn():
        assert 1 == 2, "intentional failure"

    case1 = _execute_test("FAIL-01", McpTestCategory.SERVICE, "failing assertion", failing_fn)
    assert case1.passed is False
    assert "Assertion failed: intentional failure" in (case1.error_message or "")
    assert case1.duration_ms >= 0.0

    # Test function raising unexpected Exception
    def error_fn():
        raise RuntimeError("system exploded")

    case2 = _execute_test("FAIL-02", McpTestCategory.API, "crashing exception", error_fn)
    assert case2.passed is False
    assert "RuntimeError: system exploded" in (case2.error_message or "")
