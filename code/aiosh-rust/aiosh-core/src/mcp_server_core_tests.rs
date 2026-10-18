//! AI Control Plane MCP Server Core Automated Tests Subsystem (T-03115 scaffold / T-03116 impl).
//!
//! Defines test runner abstractions, test case records, and test suite reporting envelopes
//! in compliance with SPEC-MCP-SERVER-CORE-TESTS and PoR Invariant I-2.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTestCategory {
    DataModel,
    Api,
    Service,
    Config,
    Security,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpTestCase {
    pub test_id: String,
    pub category: McpTestCategory,
    pub name: String,
    pub passed: bool,
    pub error_message: Option<String>,
    pub duration_ms: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpTestSuiteReport {
    pub suite_name: String,
    pub total_cases: usize,
    pub passed_cases: usize,
    pub failed_cases: usize,
    pub duration_seconds: f64,
    pub cases: Vec<McpTestCase>,
}

impl Default for McpTestSuiteReport {
    fn default() -> Self {
        Self {
            suite_name: "mcp_server_core_automated_tests".to_string(),
            total_cases: 0,
            passed_cases: 0,
            failed_cases: 0,
            duration_seconds: 0.0,
            cases: Vec::new(),
        }
    }
}

impl McpTestSuiteReport {
    pub fn is_success(&self) -> bool {
        self.failed_cases == 0 && self.total_cases > 0
    }

    pub fn to_json_str(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("serialization error: {}", e))
    }
}

pub fn run_all_mcp_tests() -> Result<McpTestSuiteReport, String> {
    Err("run_all_mcp_tests scaffold — implementation in T-03116".to_string())
}
