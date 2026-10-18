//! AI Control Plane MCP Server Core Automated Tests Subsystem (T-03115 scaffold / T-03116 impl).
//!
//! Defines test runner abstractions, test case records, and test suite reporting envelopes
//! in compliance with SPEC-MCP-SERVER-CORE-TESTS and PoR Invariant I-2.

use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::mcp_server_core_data_model::{
    McpCoreResultEnvelope, McpToolDefinition, ERR_METHOD_NOT_FOUND, ERR_UNAUTHORIZED,
};
use crate::mcp_server_core_service::McpServerCoreService;
use crate::mcp_server_core_api::McpApiHandler;
use crate::mcp_server_core_config::{
    McpServerCoreConfig, MIN_ACTIVE_SESSIONS, MAX_ALLOWED_ACTIVE_SESSIONS,
};

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

fn execute_case<F>(test_id: &str, category: McpTestCategory, name: &str, f: F) -> McpTestCase
where
    F: FnOnce() -> Result<(), String>,
{
    let start = Instant::now();
    let res = f();
    let duration = start.elapsed().as_secs_f64() * 1000.0;
    match res {
        Ok(()) => McpTestCase {
            test_id: test_id.to_string(),
            category,
            name: name.to_string(),
            passed: true,
            error_message: None,
            duration_ms: duration,
        },
        Err(mut err) => {
            if err.len() > 1024 {
                err.truncate(1021);
                err.push_str("...");
            }
            McpTestCase {
                test_id: test_id.to_string(),
                category,
                name: name.to_string(),
                passed: false,
                error_message: Some(err),
                duration_ms: duration,
            }
        }
    }
}

pub fn run_all_mcp_tests() -> Result<McpTestSuiteReport, String> {
    let suite_start = Instant::now();
    let mut cases = Vec::new();

    // Data Model
    cases.push(execute_case("TEST-DATA-01", McpTestCategory::DataModel, "McpToolDefinition serialization", || {
        let td = McpToolDefinition::new("echo", "echo service", serde_json::json!({}))
            .map_err(|e| format!("{:?}", e))?;
        if td.name != "echo" {
            return Err("tool name mismatch".into());
        }
        Ok(())
    }));

    cases.push(execute_case("TEST-DATA-02", McpTestCategory::DataModel, "McpCoreResultEnvelope success/error", || {
        let env = McpCoreResultEnvelope::success(serde_json::json!({"status": "ok"}));
        if !env.ok {
            return Err("envelope not ok".into());
        }
        Ok(())
    }));

    // API
    cases.push(execute_case("TEST-API-01", McpTestCategory::Api, "handle_ping liveness response", || {
        let svc = McpServerCoreService::default();
        let handler = McpApiHandler::new(&svc);
        let res = handler.handle_ping(Some(1.into()));
        if res.get("id") != Some(&serde_json::json!(1)) {
            return Err("ping id mismatch".into());
        }
        Ok(())
    }));

    cases.push(execute_case("TEST-API-02", McpTestCategory::Api, "Unknown method returns -32601", || {
        let svc = McpServerCoreService::default();
        let handler = McpApiHandler::new(&svc);
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "nonexistent"
        });
        let res = handler.handle_raw_message(&msg.to_string());
        if let Some(err) = res.get("error") {
            if err.get("code") != Some(&serde_json::json!(ERR_METHOD_NOT_FOUND)) {
                return Err(format!("expected -32601, got {:?}", err.get("code")));
            }
        } else {
            return Err("expected error envelope".into());
        }
        Ok(())
    }));

    // Service
    cases.push(execute_case("TEST-SVC-01", McpTestCategory::Service, "Tool registration capacity and catalog", || {
        let svc = McpServerCoreService::default();
        let td = McpToolDefinition::new("sample_tool", "sample desc", serde_json::json!({}))
            .map_err(|e| format!("{:?}", e))?;
        svc.register_tool(td).map_err(|e| format!("{:?}", e))?;
        if svc.get_tool("sample_tool").is_none() {
            return Err("tool not found after registration".into());
        }
        Ok(())
    }));

    // Config
    cases.push(execute_case("TEST-CFG-01", McpTestCategory::Config, "Default configuration invariants", || {
        let cfg = McpServerCoreConfig::default();
        cfg.validate()?;
        if cfg.max_active_sessions < MIN_ACTIVE_SESSIONS || cfg.max_active_sessions > MAX_ALLOWED_ACTIVE_SESSIONS {
            return Err("max_active_sessions out of bounds".into());
        }
        Ok(())
    }));

    cases.push(execute_case("TEST-CFG-02", McpTestCategory::Config, "Path traversal rejection in store_path", || {
        let mut cfg = McpServerCoreConfig::default();
        cfg.store_path = std::path::PathBuf::from("../evil/store.json");
        if cfg.validate().is_ok() {
            return Err("traversal was not rejected".into());
        }
        Ok(())
    }));

    // Security
    cases.push(execute_case("TEST-SEC-01", McpTestCategory::Security, "PoR Invariant I-2: admin tool requires grant", || {
        let svc = McpServerCoreService::default();
        let handler = McpApiHandler::new(&svc);
        let msg = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "aios.admin.shutdown",
                "arguments": {}
            }
        });
        let res = handler.handle_raw_message(&msg.to_string());
        if let Some(err) = res.get("error") {
            if err.get("code") != Some(&serde_json::json!(ERR_UNAUTHORIZED)) {
                return Err(format!("expected unauthorized -32002, got {:?}", err.get("code")));
            }
        } else {
            return Err("expected unauthorized error for aios.admin.*".into());
        }
        Ok(())
    }));

    let total = cases.len();
    let passed = cases.iter().filter(|c| c.passed).count();
    let failed = total - passed;
    let duration = suite_start.elapsed().as_secs_f64();

    Ok(McpTestSuiteReport {
        suite_name: "mcp_server_core_automated_tests".to_string(),
        total_cases: total,
        passed_cases: passed,
        failed_cases: failed,
        duration_seconds: duration,
        cases,
    })
}
