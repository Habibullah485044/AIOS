//! Unit tests for MCP Server Core MCP/API surface (T-03097).

use serde_json::json;
use aiosh_core::mcp_server_core_api::*;
use aiosh_core::mcp_server_core_data_model::*;
use aiosh_core::mcp_server_core_api::PROTOCOL_VERSION;
use aiosh_core::mcp_server_core_service::*;

#[test]
fn test_unit_case1_valid_api_requests() {
    let service = McpServerCoreService::new();
    let tool = McpToolDefinition::new("aios.fs.read", "Read file", json!({"type": "object"})).unwrap();
    service.register_tool(tool).unwrap();
    let handler = McpApiHandler::new(&service);

    // 1. Ping
    let resp = handler.handle_raw_message(r#"{"jsonrpc": "2.0", "id": 10, "method": "ping"}"#);
    assert_eq!(resp.get("jsonrpc").and_then(|v| v.as_str()), Some("2.0"));
    assert_eq!(resp.get("id").and_then(|v| v.as_i64()), Some(10));
    assert_eq!(resp["result"]["status"], "ok");

    // 2. Initialize
    let resp = handler.handle_raw_message(r#"{"jsonrpc": "2.0", "id": 11, "method": "initialize", "params": {"clientInfo": {"name": "test-agent", "version": "1.0.0"}}}"#);
    assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);

    // 3. Tools list
    let resp = handler.handle_raw_message(r#"{"jsonrpc": "2.0", "id": 12, "method": "tools/list"}"#);
    assert_eq!(resp["result"]["tools"].as_array().unwrap().len(), 1);

    // 4. Tools call
    let resp = handler.handle_raw_message(r#"{"jsonrpc": "2.0", "id": 13, "method": "tools/call", "params": {"name": "aios.fs.read", "arguments": {}}}"#);
    assert_eq!(resp["result"]["isError"], false);
}

#[test]
fn test_unit_case2_invalid_api_inputs() {
    let service = McpServerCoreService::new();
    let handler = McpApiHandler::new(&service);

    // Parse error
    let resp = handler.handle_raw_message("not valid json");
    assert_eq!(resp["error"]["code"], -32700);

    // Invalid jsonrpc version
    let resp = handler.handle_raw_message(r#"{"jsonrpc": "1.0", "id": 1, "method": "ping"}"#);
    assert_eq!(resp["error"]["code"], ERR_INVALID_REQUEST);

    // Missing method
    let resp = handler.handle_raw_message(r#"{"jsonrpc": "2.0", "id": 2}"#);
    assert_eq!(resp["error"]["code"], ERR_INVALID_REQUEST);

    // Method not found
    let resp = handler.handle_raw_message(r#"{"jsonrpc": "2.0", "id": 3, "method": "unknown/method"}"#);
    assert_eq!(resp["error"]["code"], ERR_METHOD_NOT_FOUND);

    // NUL byte in tool name
    let resp = handler.handle_raw_message("{\"jsonrpc\": \"2.0\", \"id\": 4, \"method\": \"tools/call\", \"params\": {\"name\": \"bad\\u0000tool\"}}");
    assert_eq!(resp["error"]["code"], ERR_INVALID_PARAMS);
}

#[test]
fn test_unit_case3_boundary_values() {
    let service = McpServerCoreService::new();
    let tool = McpToolDefinition::new("aios.echo", "Echo input", json!({"type": "object"})).unwrap();
    service.register_tool(tool).unwrap();
    let handler = McpApiHandler::new(&service);

    // Valid empty arguments
    let resp = handler.handle_raw_message(r#"{"jsonrpc": "2.0", "id": 20, "method": "tools/call", "params": {"name": "aios.echo", "arguments": {}}}"#);
    assert_eq!(resp["result"]["isError"], false);

    // Oversized arguments payload > 1 MiB
    let huge = "x".repeat(MAX_ARGUMENTS_SIZE + 10);
    let raw = format!(r#"{{"jsonrpc": "2.0", "id": 21, "method": "tools/call", "params": {{"name": "aios.echo", "arguments": {{"data": "{}"}}}}}}"#, huge);
    let resp = handler.handle_raw_message(&raw);
    assert_eq!(resp["error"]["code"], ERR_BOUNDS_EXCEEDED);
}

#[test]
fn test_unit_case4_primary_failure_modes() {
    let service = McpServerCoreService::new();
    let tool = McpToolDefinition::new("aios.admin.restart", "Restart daemon", json!({"type": "object"})).unwrap();
    service.register_tool(tool).unwrap();
    let handler = McpApiHandler::new(&service);

    // 1. Tool not found
    let resp = handler.handle_raw_message(r#"{"jsonrpc": "2.0", "id": 30, "method": "tools/call", "params": {"name": "aios.missing"}}"#);
    assert!(resp.get("error").is_some());

    // 2. Privileged tool without grant -> ERR_UNAUTHORIZED (-32002)
    let resp = handler.handle_raw_message(r#"{"jsonrpc": "2.0", "id": 31, "method": "tools/call", "params": {"name": "aios.admin.restart", "arguments": {}}}"#);
    assert_eq!(resp["error"]["code"], ERR_UNAUTHORIZED);

    // 3. Privileged tool with grant -> succeeds
    let resp = handler.handle_raw_message(r#"{"jsonrpc": "2.0", "id": 32, "method": "tools/call", "params": {"name": "aios.admin.restart", "arguments": {}, "grant": "grant_token_123"}}"#);
    assert_eq!(resp["result"]["isError"], false);
}
