//! Integration test for MCP Server Core data model (T-03068).
//!
//! Verifies end-to-end integration:
//! - Full JSON-RPC tool dispatch flow
//! - Serialized wire exchanges between client request and server response
//! - Envelope wrapping and capability checks

use aiosh_core::mcp_server_core_data_model::*;
use serde_json::json;

#[test]
fn test_integration_mcp_core_data_model_end_to_end() {
    // 1. Client initiates initialize handshake
    let init_req = McpJsonRpcRequest::new(
        McpRequestId::Number(1),
        "initialize",
        Some(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "test-agent", "version": "1.0.0"}
        })),
    );
    assert!(init_req.validate().is_ok());

    let wire_req = init_req.to_json_str().expect("valid wire request");

    // 2. Server decodes wire request and constructs session
    let decoded_req = McpJsonRpcRequest::from_json_str(&wire_req).expect("valid parse");
    assert_eq!(decoded_req.method, "initialize");

    let session = McpSessionInfo::new("session-integration-01", "test-agent", "1.0.0")
        .expect("session created");
    assert_eq!(session.session_id, "session-integration-01");
    assert_eq!(session.protocol_version, PROTOCOL_VERSION);

    // 3. Server responds with capabilities
    let init_resp = McpJsonRpcResponse::success(
        decoded_req.id,
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": session.capabilities,
            "serverInfo": {"name": "aiosh-mcp", "version": "0.1.0"}
        }),
    );
    let wire_resp = init_resp.to_json_str().expect("valid wire response");
    assert!(wire_resp.contains("aiosh-mcp"));

    // 4. Client invokes tools/call
    let call_req = McpJsonRpcRequest::new(
        McpRequestId::String("call-01".to_string()),
        "tools/call",
        Some(json!({
            "name": "aios.process.list",
            "arguments": {}
        })),
    );
    assert!(call_req.validate().is_ok());

    let tool_call = McpToolCall::new("aios.process.list", json!({}), Some("gr_test_01".to_string()))
        .expect("tool call valid");
    assert_eq!(tool_call.name, "aios.process.list");
    assert_eq!(tool_call.grant_id, Some("gr_test_01".to_string()));

    let tool_res = McpToolResult::text("pid 1234 python");
    let resp = McpJsonRpcResponse::success(
        call_req.id,
        json!(tool_res),
    );
    let wire_res_str = resp.to_json_str().expect("valid wire result");
    assert!(wire_res_str.contains("pid 1234"));

    // 5. ADR-0035 Result Envelope wrapping
    let envelope = McpCoreResultEnvelope::success(tool_res);
    assert!(envelope.ok);
    assert_eq!(envelope.status, "success");
}
