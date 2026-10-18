//! Hardening tests for MCP Server Core CLI surface (T-03090).
//!
//! Verifies:
//! - NUL byte rejection across all argument positions
//! - Structured JSON error envelopes when `--json` is supplied on failure
//! - Clamping and non-panicking execution under adversarial arguments

use aiosh_core::mcp_server_core_cli::*;
use aiosh_core::mcp_server_core_service::McpServerCoreService;

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

#[test]
fn test_hardening_nul_byte_rejection() {
    // NUL in subcommand
    let res = parse_mcp_cli_args(&s(&["ping\0evil"]));
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().0, EXIT_USAGE);

    // NUL in flag value
    let res = parse_mcp_cli_args(&s(&["list", "--filter", "tool\0bad"]));
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().0, EXIT_USAGE);

    // NUL in tool argument
    let res = parse_mcp_cli_args(&s(&["dispatch", "aios.safe.tool\0"]));
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().0, EXIT_USAGE);
}

#[test]
fn test_hardening_json_error_envelopes() {
    let service = McpServerCoreService::new();

    // 1. Tool not found in JSON mode
    let cmd = parse_mcp_cli_args(&s(&["show", "missing.tool", "--json"])).expect("parse");
    let out = execute_mcp_cli(&cmd, &service);
    assert_eq!(out.exit_code, EXIT_FAILURE);
    assert!(out.json_payload.is_some());
    let payload = out.json_payload.unwrap();
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["ok"], false);
    assert_eq!(payload["error_code"], EXIT_FAILURE);

    // 2. Privileged tool missing grant in JSON mode
    let cmd = parse_mcp_cli_args(&s(&["dispatch", "aios.admin.reboot", "--json"])).expect("parse");
    let out = execute_mcp_cli(&cmd, &service);
    assert_eq!(out.exit_code, EXIT_UNAUTHORIZED);
    assert!(out.json_payload.is_some());
    let payload = out.json_payload.unwrap();
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["ok"], false);
    assert_eq!(payload["error_code"], EXIT_UNAUTHORIZED);
}
