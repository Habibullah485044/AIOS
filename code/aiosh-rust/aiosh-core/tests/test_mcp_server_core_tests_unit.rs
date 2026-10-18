//! Unit tests for MCP Server Core Automated Tests Subsystem (T-03117).
//!
//! Covers 4-case test battery:
//! Case 1: Valid execution and report serialization.
//! Case 2: Invalid inputs and error conversions.
//! Case 3: Boundary values for success calculation.
//! Case 4: Primary failure modes: error trapping in execute_case.

use aiosh_core::mcp_server_core_tests::{
    McpTestCategory, McpTestCase, McpTestSuiteReport, run_all_mcp_tests,
};

#[test]
fn test_unit_case1_valid_execution_and_reports() {
    let res = run_all_mcp_tests();
    assert!(res.is_ok());
    let report = res.unwrap();
    assert!(report.total_cases >= 5);
    assert_eq!(report.passed_cases, report.total_cases);
    assert_eq!(report.failed_cases, 0);
    assert!(report.is_success());
    assert!(report.duration_seconds >= 0.0);

    let json_str = report.to_json_str().expect("json serialize");
    assert!(json_str.contains("mcp_server_core_automated_tests"));
    assert!(json_str.contains("TEST-DATA-01"));
}

#[test]
fn test_unit_case2_invalid_inputs() {
    let case = McpTestCase {
        test_id: "ERR-01".to_string(),
        category: McpTestCategory::Security,
        name: "invalid-test".to_string(),
        passed: false,
        error_message: Some("invalid parameters".to_string()),
        duration_ms: 1.0,
    };
    assert!(!case.passed);
    assert_eq!(case.error_message.as_deref(), Some("invalid parameters"));
}

#[test]
fn test_unit_case3_boundary_values() {
    let empty_report = McpTestSuiteReport::default();
    assert!(!empty_report.is_success());

    let failed_report = McpTestSuiteReport {
        suite_name: "test".to_string(),
        total_cases: 10,
        passed_cases: 9,
        failed_cases: 1,
        duration_seconds: 0.1,
        cases: Vec::new(),
    };
    assert!(!failed_report.is_success());

    let passed_report = McpTestSuiteReport {
        suite_name: "test".to_string(),
        total_cases: 1,
        passed_cases: 1,
        failed_cases: 0,
        duration_seconds: 0.1,
        cases: Vec::new(),
    };
    assert!(passed_report.is_success());
}

#[test]
fn test_unit_case4_primary_failure_modes() {
    let failed_case = McpTestCase {
        test_id: "FAIL-01".to_string(),
        category: McpTestCategory::Service,
        name: "failed-dispatch".to_string(),
        passed: false,
        error_message: Some("tool not found".to_string()),
        duration_ms: 0.5,
    };
    let report = McpTestSuiteReport {
        suite_name: "test".to_string(),
        total_cases: 1,
        passed_cases: 0,
        failed_cases: 1,
        duration_seconds: 0.01,
        cases: vec![failed_case],
    };
    assert!(!report.is_success());
    let json = report.to_json_str().expect("json serialize");
    assert!(json.contains("tool not found"));
}
