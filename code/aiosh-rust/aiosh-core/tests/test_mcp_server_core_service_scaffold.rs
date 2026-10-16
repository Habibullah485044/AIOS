//! Scaffold test for MCP Server Core service (T-03075).

use aiosh_core::mcp_server_core_service::*;
use aiosh_core::mcp_server_core_data_model::*;
use serde_json::json;

#[test]
fn test_mcp_core_service_scaffold_types() {
    let service = McpServerCoreService::new();
    let tool_def = McpToolDefinition::new("aios.test.ping", "ping test", json!({})).expect("valid tool");
    assert!(service.register_tool(tool_def).is_ok());

    let session = service.create_session("sess-scaffold-01", "agent", "1.0").expect("session created");
    assert_eq!(session.status, McpSessionStatus::Active);

    let call = McpToolCall::new("aios.test.ping", json!({}), None).expect("call valid");
    let result = service.dispatch_tool_call(call);
    assert!(result.is_ok());
}
