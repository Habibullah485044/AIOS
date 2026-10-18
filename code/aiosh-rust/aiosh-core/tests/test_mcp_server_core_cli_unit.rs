//! Unit tests for MCP Server Core CLI surface (T-03087).
//!
//! Standard 4-case testing battery:
//! 1. Valid input (ping, list, show, safe dispatch, sessions prune)
//! 2. Invalid input (unknown subcommands, unknown flags, missing args)
//! 3. Boundary values (MAX_ARGUMENTS_SIZE 1 MiB, timeout clamp 1..300)
//! 4. Primary failure modes (tool not found, privileged unauthorized tool)

use aiosh_core::mcp_server_core_cli::*;
use aiosh_core::mcp_server_core_data_model::*;
use aiosh_core::mcp_server_core_service::McpServerCoreService;
use serde_json::json;

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

#[test]
fn test_unit_case1_valid_cli_commands() {
    let service = McpServerCoreService::new();

    // Register a valid tool
    let tool = McpToolDefinition::new("aios.fs.read", "Read file", json!({"type": "object"})).unwrap();
    service.register_tool(tool).unwrap();

    // 1. Ping
    let ping_cmd = parse_mcp_cli_args(&s(&["ping", "--json"])).expect("parse ping");
    let out = execute_mcp_cli(&ping_cmd, &service);
    assert_eq!(out.exit_code, EXIT_SUCCESS);
    assert!(out.json_payload.is_some());

    // 2. List
    let list_cmd = parse_mcp_cli_args(&s(&["list", "--json"])).expect("parse list");
    let out = execute_mcp_cli(&list_cmd, &service);
    assert_eq!(out.exit_code, EXIT_SUCCESS);

    // 3. Show
    let show_cmd = parse_mcp_cli_args(&s(&["show", "aios.fs.read", "--json"])).expect("parse show");
    let out = execute_mcp_cli(&show_cmd, &service);
    assert_eq!(out.exit_code, EXIT_SUCCESS);

    // 4. Dispatch valid
    let disp_cmd = parse_mcp_cli_args(&s(&["dispatch", "aios.fs.read", "--args", "{\"path\":\"/tmp/test\"}"])).expect("parse dispatch");
    let out = execute_mcp_cli(&disp_cmd, &service);
    assert_eq!(out.exit_code, EXIT_SUCCESS);

    // 5. Sessions prune
    let sess_cmd = parse_mcp_cli_args(&s(&["sessions", "--prune", "0", "--json"])).expect("parse sessions");
    let out = execute_mcp_cli(&sess_cmd, &service);
    assert_eq!(out.exit_code, EXIT_SUCCESS);
}

#[test]
fn test_unit_case2_invalid_cli_inputs() {
    // 1. Empty args
    let err = parse_mcp_cli_args(&[]).unwrap_err();
    assert_eq!(err.0, EXIT_USAGE);

    // 2. Unknown subcommand
    let err = parse_mcp_cli_args(&s(&["unknown_cmd"])).unwrap_err();
    assert_eq!(err.0, EXIT_USAGE);

    // 3. Unknown flag
    let err = parse_mcp_cli_args(&s(&["list", "--bogus-flag"])).unwrap_err();
    assert_eq!(err.0, EXIT_USAGE);

    // 4. Missing required parameters
    let err = parse_mcp_cli_args(&s(&["show"])).unwrap_err();
    assert_eq!(err.0, EXIT_USAGE);

    let err = parse_mcp_cli_args(&s(&["dispatch"])).unwrap_err();
    assert_eq!(err.0, EXIT_USAGE);
}

#[test]
fn test_unit_case3_boundary_values() {
    let service = McpServerCoreService::new();
    let tool = McpToolDefinition::new("aios.test.bound", "Boundary tool", json!({})).unwrap();
    service.register_tool(tool).unwrap();

    // Max arguments limit violation (> 1 MiB)
    let huge_args = format!("{{\"pad\":\"{}\"}}", "x".repeat(MAX_ARGUMENTS_SIZE + 1024));
    let huge_cmd = parse_mcp_cli_args(&s(&["dispatch", "aios.test.bound", "--args", &huge_args])).unwrap();
    let out = execute_mcp_cli(&huge_cmd, &service);
    assert_eq!(out.exit_code, EXIT_USAGE);

    // Timeout boundary clamping (valid dispatch with clamped timeout)
    let bound_cmd = parse_mcp_cli_args(&s(&["dispatch", "aios.test.bound", "--timeout", "999999", "--json"])).unwrap();
    let out = execute_mcp_cli(&bound_cmd, &service);
    assert_eq!(out.exit_code, EXIT_SUCCESS);
}

#[test]
fn test_unit_case4_primary_failure_modes() {
    let service = McpServerCoreService::new();

    // 1. Tool not found
    let miss_cmd = parse_mcp_cli_args(&s(&["show", "nonexistent.tool"])).unwrap();
    let out = execute_mcp_cli(&miss_cmd, &service);
    assert_eq!(out.exit_code, EXIT_FAILURE);

    // 2. Dispatch missing tool
    let miss_disp = parse_mcp_cli_args(&s(&["dispatch", "nonexistent.tool"])).unwrap();
    let out = execute_mcp_cli(&miss_disp, &service);
    assert_eq!(out.exit_code, EXIT_FAILURE);

    // 3. Privileged tool missing grant token (fail closed with EXIT_UNAUTHORIZED = 3)
    let priv_disp = parse_mcp_cli_args(&s(&["dispatch", "aios.admin.shutdown"])).unwrap();
    let out = execute_mcp_cli(&priv_disp, &service);
    assert_eq!(out.exit_code, EXIT_UNAUTHORIZED);
}
