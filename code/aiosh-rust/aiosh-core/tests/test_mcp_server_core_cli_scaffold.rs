//! Scaffold test for MCP Server Core CLI surface (T-03085).

use aiosh_core::mcp_server_core_cli::*;
use aiosh_core::mcp_server_core_service::McpServerCoreService;

#[test]
fn test_mcp_cli_scaffold_types_and_ping() {
    let service = McpServerCoreService::new();

    // Verify parser on ping
    let args = vec!["ping".to_string(), "--json".to_string()];
    let parsed = parse_mcp_cli_args(&args).expect("valid parse");
    assert_eq!(parsed, McpCliSubcommand::Ping { json: true });

    // Verify execution of ping
    let output = execute_mcp_cli(&parsed, &service);
    assert_eq!(output.exit_code, EXIT_SUCCESS);
    assert!(output.message.contains("\"status\":\"ok\"") || output.message.contains("\"status\": \"ok\""));
}
