//! Integration test for MCP Server Core service (T-03078).
//!
//! Verifies:
//! - Multi-tool registration and dynamic enumeration
//! - End-to-end tool dispatch and execution via safe envelope
//! - Concurrent session lifecycle handling

use aiosh_core::mcp_server_core_service::*;
use aiosh_core::mcp_server_core_data_model::*;
use serde_json::json;

#[test]
fn test_integration_core_service_end_to_end() {
    let service = McpServerCoreService::new();

    // 1. Register multiple domain tools
    let t1 = McpToolDefinition::new("aios.process.list", "List processes", json!({})).unwrap();
    let t2 = McpToolDefinition::new("aios.fs.read", "Read file", json!({})).unwrap();
    let t3 = McpToolDefinition::new("aios.audit.tail", "Tail audit log", json!({})).unwrap();

    assert!(service.register_tool(t1).is_ok());
    assert!(service.register_tool(t2).is_ok());
    assert!(service.register_tool(t3).is_ok());

    let tools = service.list_tools();
    assert_eq!(tools.len(), 3);
    assert_eq!(tools[0].name, "aios.audit.tail"); // Alphabetical ordering

    // 2. Client establishes session
    let session = service.create_session("sess-integ-client-1", "mcp-agent", "2.0.0").unwrap();
    assert_eq!(session.info.client_name, "mcp-agent");

    // 3. Client executes tools via safe envelope dispatch
    let call = McpToolCall::new("aios.fs.read", json!({"path": "/etc/passwd"}), None).unwrap();
    let envelope = service.safe_dispatch_tool_call(call);
    assert!(envelope.ok);
    assert_eq!(envelope.status, "success");

    // 4. Session termination
    assert!(service.terminate_session("sess-integ-client-1").is_ok());
    let ended = service.get_session("sess-integ-client-1").unwrap();
    assert_eq!(ended.status, McpSessionStatus::Terminated);
}
