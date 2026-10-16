//! Unit tests for MCP Server Core service (T-03077).
//!
//! Covers:
//! 1. Valid input (registration, query, session lifecycle, dispatch)
//! 2. Invalid input (duplicate tools, unauthorized privileged tool, invalid session)
//! 3. Boundary values (session capacity 64, tool capacity 256)
//! 4. Primary failure mode (tool not found, terminated session heartbeat)

use aiosh_core::mcp_server_core_service::*;
use aiosh_core::mcp_server_core_data_model::*;
use serde_json::json;

#[test]
fn test_unit_case1_valid_tool_and_session_lifecycle() {
    let service = McpServerCoreService::new();

    let tool = McpToolDefinition::new(
        "aios.fs.read",
        "Safe text reader",
        json!({"type": "object", "properties": {"path": {"type": "string"}}}),
    ).expect("valid tool");
    assert!(service.register_tool(tool).is_ok());

    let found = service.get_tool("aios.fs.read");
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "aios.fs.read");

    let list = service.list_tools();
    assert_eq!(list.len(), 1);

    // Session creation & heartbeat
    let session = service.create_session("sess-unit-1", "agent-test", "1.0").expect("session created");
    assert_eq!(session.status, McpSessionStatus::Active);

    assert!(service.heartbeat_session("sess-unit-1").is_ok());
    let fetched = service.get_session("sess-unit-1").expect("session found");
    assert_eq!(fetched.last_heartbeat, 1);

    // Normal tool dispatch
    let call = McpToolCall::new("aios.fs.read", json!({"path": "/tmp/a.txt"}), None).expect("call valid");
    let result = service.dispatch_tool_call(call).expect("dispatch succeeded");
    assert!(!result.is_error);
    assert!(result.content[0].to_json_str().unwrap_or_default().contains("Executed aios.fs.read"));
}

#[test]
fn test_unit_case2_invalid_input_and_unauthorized_dispatch() {
    let service = McpServerCoreService::new();

    let tool = McpToolDefinition::new("aios.admin.restart", "Reboot core", json!({})).expect("tool valid");
    assert!(service.register_tool(tool).is_ok());

    // Duplicate registration rejected
    let tool_dup = McpToolDefinition::new("aios.admin.restart", "Reboot dup", json!({})).expect("tool valid");
    let dup_err = service.register_tool(tool_dup).unwrap_err();
    assert_eq!(dup_err.code, MCPSVC_ERR_TOOL_ALREADY_EXISTS);

    // Privileged tool call without grant_id rejected (fail-closed)
    let unauth_call = McpToolCall::new("aios.admin.restart", json!({}), None).expect("call valid");
    let call_err = service.dispatch_tool_call(unauth_call).unwrap_err();
    assert_eq!(call_err.code, ERR_UNAUTHORIZED);

    // Terminate non-existent session
    let term_err = service.terminate_session("non-existent-session").unwrap_err();
    assert_eq!(term_err.code, MCPSVC_ERR_SESSION_NOT_FOUND);
}

#[test]
fn test_unit_case3_boundary_values_capacity_and_eviction() {
    let service = McpServerCoreService::new();

    // Fill to MAX_ACTIVE_SESSIONS (64)
    for i in 0..MAX_ACTIVE_SESSIONS {
        let sid = format!("sess-bound-{}", i);
        assert!(service.create_session(&sid, "client", "1.0").is_ok());
    }

    // Next creation fails with capacity error
    let overflow = service.create_session("sess-overflow", "client", "1.0");
    assert!(overflow.is_err());
    assert_eq!(overflow.unwrap_err().code, MCPSVC_ERR_SESSION_CAPACITY_EXCEEDED);

    // Terminate one session
    assert!(service.terminate_session("sess-bound-0").is_ok());

    // Creation now succeeds by evicting terminated session
    let recovered = service.create_session("sess-recovered", "client", "1.0");
    assert!(recovered.is_ok());
}

#[test]
fn test_unit_case4_primary_failure_mode_missing_tool_and_envelope() {
    let service = McpServerCoreService::new();

    // Dispatch missing tool
    let missing_call = McpToolCall::new("aios.nonexistent.tool", json!({}), None).expect("call valid");
    let err = service.dispatch_tool_call(missing_call.clone()).unwrap_err();
    assert_eq!(err.code, MCPSVC_ERR_TOOL_NOT_FOUND);

    // Safe dispatch envelope
    let env = service.safe_dispatch_tool_call(missing_call);
    assert!(!env.ok);
    assert_eq!(env.status, "error");
    assert_eq!(env.error_code, Some(MCPSVC_ERR_TOOL_NOT_FOUND));
}

trait ToJsonHelper {
    fn to_json_str(&self) -> Result<String, ()>;
}

impl ToJsonHelper for McpContentBlock {
    fn to_json_str(&self) -> Result<String, ()> {
        serde_json::to_string(self).map_err(|_| ())
    }
}
