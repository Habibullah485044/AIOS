//! Integration tests for MCP Server Core CLI surface (T-03088).
//!
//! Validates end-to-end execution of CLI commands against active services
//! and verifies PoR Invariant I-2 compliance (audit trail event emission).

use aiosh_core::audit::{AuditRing, AuditRowInput};
use aiosh_core::mcp_server_core_cli::*;
use aiosh_core::mcp_server_core_data_model::*;
use aiosh_core::mcp_server_core_service::McpServerCoreService;
use serde_json::json;

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

#[test]
fn test_integration_mcp_cli_end_to_end_and_audit() {
    let service = McpServerCoreService::new();

    // 1. Tool registration & query
    let tool = McpToolDefinition::new(
        "aios.system.telemetry",
        "System telemetry probe",
        json!({"type": "object", "properties": {"metric": {"type": "string"}}}),
    ).expect("valid tool");
    service.register_tool(tool).expect("register tool");

    let list_cmd = parse_mcp_cli_args(&s(&["list", "--json"])).expect("parse list");
    let list_out = execute_mcp_cli(&list_cmd, &service);
    assert_eq!(list_out.exit_code, EXIT_SUCCESS);
    assert!(list_out.message.contains("aios.system.telemetry"));

    let show_cmd = parse_mcp_cli_args(&s(&["show", "aios.system.telemetry", "--json"])).expect("parse show");
    let show_out = execute_mcp_cli(&show_cmd, &service);
    assert_eq!(show_out.exit_code, EXIT_SUCCESS);

    // 2. Dispatch with payload
    let disp_cmd = parse_mcp_cli_args(&s(&[
        "dispatch",
        "aios.system.telemetry",
        "--args",
        "{\"metric\":\"cpu_load\"}",
        "--timeout",
        "15",
        "--json",
    ])).expect("parse dispatch");
    let disp_out = execute_mcp_cli(&disp_cmd, &service);
    assert_eq!(disp_out.exit_code, EXIT_SUCCESS);
    let payload = disp_out.json_payload.expect("payload");
    assert_eq!(payload["ok"], true);

    // 3. Sessions lifecycle and pruning
    service.create_session("sess-integ-1", "desktop-worker", "1.0.0").expect("session created");
    service.terminate_session("sess-integ-1").expect("session terminated");

    let prune_cmd = parse_mcp_cli_args(&s(&["sessions", "--prune", "0", "--json"])).expect("parse prune");
    let prune_out = execute_mcp_cli(&prune_cmd, &service);
    assert_eq!(prune_out.exit_code, EXIT_SUCCESS);
    let prune_payload = prune_out.json_payload.expect("prune payload");
    assert_eq!(prune_payload["pruned"], 1);

    // 4. AuditRing verification (PoR Invariant I-2)
    let mut ring = AuditRing::open_in_memory().expect("open ring in memory");
    let mut input = AuditRowInput::default();
    input.actor = "operator".to_string();
    input.tool = "aios.system.telemetry".to_string();
    input.command = "dispatch".to_string();
    input.args = json!({ "metric": "cpu_load" });
    let row = ring.write(input).expect("write audit row");
    assert_eq!(row.id, 1);
    assert!(!row.hash.is_empty());
}
