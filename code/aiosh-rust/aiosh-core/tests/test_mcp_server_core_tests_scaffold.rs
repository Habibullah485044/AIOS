//! Scaffold test for MCP Server Core Automated Tests (T-03115).

use aiosh_core::mcp_server_core_tests::{
    McpTestCategory, McpTestCase, McpTestSuiteReport, run_all_mcp_tests,
};

#[test]
fn test_mcp_tests_scaffold_types() {
    let case = McpTestCase {
        test_id: "TEST-01".to_string(),
        category: McpTestCategory::DataModel,
        name: "test-data-model".to_string(),
        passed: true,
        error_message: None,
        duration_ms: 2.5,
    };
    assert_eq!(case.test_id, "TEST-01");
    assert!(case.passed);

    let report = McpTestSuiteReport {
        suite_name: "test_suite".to_string(),
        total_cases: 1,
        passed_cases: 1,
        failed_cases: 0,
        duration_seconds: 0.05,
        cases: vec![case],
    };
    assert!(report.is_success());
    let json = report.to_json_str().expect("json serialize");
    assert!(json.contains("TEST-01"));
}

#[test]
fn test_mcp_tests_run_all() {
    let res = run_all_mcp_tests();
    assert!(res.is_ok());
    let report = res.unwrap();
    assert!(report.is_success());
    assert!(report.total_cases >= 5);
}
