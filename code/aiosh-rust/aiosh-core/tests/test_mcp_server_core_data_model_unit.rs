//! Unit tests for MCP Server Core data model (T-03067).
//!
//! Covers:
//! 1. Valid input (roundtrip JSON-RPC, tool defs, content blocks)
//! 2. Invalid input (bidi/control chars, missing jsonrpc 2.0, bad identifiers)
//! 3. Boundary values (64-char names, 1024-char descriptions)
//! 4. Primary failure mode (parse errors, oversized payload rejection)

use aiosh_core::mcp_server_core_data_model::*;
use serde_json::json;

#[test]
fn test_unit_case1_valid_input_roundtrip() {
    let req = McpJsonRpcRequest::new(
        McpRequestId::String("req-101".to_string()),
        "tools/call",
        Some(json!({
            "name": "aios.fs.read",
            "arguments": {"path": "/etc/hosts"}
        })),
    );
    assert!(req.validate().is_ok());

    let json_str = req.to_json_str().expect("serialization should succeed");
    assert!(json_str.contains("req-101"));
    assert!(json_str.contains("tools/call"));

    let parsed = McpJsonRpcRequest::from_json_str(&json_str).expect("parsing should succeed");
    assert_eq!(parsed.id, McpRequestId::String("req-101".to_string()));
    assert_eq!(parsed.method, "tools/call");

    let tool_def = McpToolDefinition::new(
        "aios.process.list",
        "List running processes safely",
        json!({"type": "object", "properties": {}}),
    ).expect("valid tool def");
    assert_eq!(tool_def.name, "aios.process.list");

    let tool_res = McpToolResult::text("process-1, process-2");
    assert!(!tool_res.is_error);
    assert_eq!(tool_res.content.len(), 1);

    let session = McpSessionInfo::new("sess-123", "gemini-cli", "1.0.0").expect("valid session");
    assert_eq!(session.session_id, "sess-123");
    assert_eq!(session.protocol_version, PROTOCOL_VERSION);
}

#[test]
fn test_unit_case2_invalid_input_sanitization_and_errors() {
    // Missing jsonrpc 2.0
    let invalid_jsonrpc = McpJsonRpcRequest {
        jsonrpc: "1.0".to_string(),
        id: McpRequestId::Number(1),
        method: "ping".to_string(),
        params: None,
    };
    let err = invalid_jsonrpc.validate().unwrap_err();
    assert_eq!(err.code, ERR_INVALID_REQUEST);

    // Empty method name
    let empty_method = McpJsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: McpRequestId::Number(1),
        method: "".to_string(),
        params: None,
    };
    assert_eq!(empty_method.validate().unwrap_err().code, ERR_INVALID_REQUEST);

    // Trojan Source bidi injection in tool name
    let bidi_tool_name = "aios\u{202E}evil_tool";
    let res = McpToolDefinition::new(
        bidi_tool_name,
        "Malicious description",
        json!({"type": "object"}),
    );
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().code, ERR_SANITIZATION_FAILED);

    // Control character injection in session ID
    let ctrl_session_id = "session\x07bell";
    let sres = McpSessionInfo::new(ctrl_session_id, "agent", "0.1");
    assert!(sres.is_err());
    assert_eq!(sres.unwrap_err().code, ERR_SANITIZATION_FAILED);

    // Invalid characters in identifier
    let bad_ident = "tool name with spaces";
    let bres = McpToolDefinition::new(bad_ident, "desc", json!({}));
    assert!(bres.is_err());
    assert_eq!(bres.unwrap_err().code, ERR_INVALID_PARAMS);
}

#[test]
fn test_unit_case3_boundary_values() {
    // Exactly 64 character tool name (boundary limit)
    let exact_64_name = "a".repeat(64);
    let tool_64 = McpToolDefinition::new(
        &exact_64_name,
        "valid description",
        json!({}),
    );
    assert!(tool_64.is_ok());

    // 65 character tool name (exceeds limit)
    let over_64_name = "a".repeat(65);
    let tool_65 = McpToolDefinition::new(
        &over_64_name,
        "valid description",
        json!({}),
    );
    assert!(tool_65.is_err());
    assert_eq!(tool_65.unwrap_err().code, ERR_BOUNDS_EXCEEDED);

    // Exactly 1024 character description
    let exact_1024_desc = "x".repeat(1024);
    let tool_1024 = McpToolDefinition::new(
        "valid_tool",
        &exact_1024_desc,
        json!({}),
    );
    assert!(tool_1024.is_ok());

    // 1025 character description
    let over_1024_desc = "x".repeat(1025);
    let tool_1025 = McpToolDefinition::new(
        "valid_tool",
        &over_1024_desc,
        json!({}),
    );
    assert!(tool_1025.is_err());
    assert_eq!(tool_1025.unwrap_err().code, ERR_BOUNDS_EXCEEDED);
}

#[test]
fn test_unit_case4_primary_failure_mode_parse_error() {
    // Malformed JSON string
    let bad_json = "{\"jsonrpc\": \"2.0\", \"id\": 1, \"method\": ";
    let res = McpJsonRpcRequest::from_json_str(bad_json);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().code, ERR_PARSE_ERROR);

    // Oversized payload rejection
    let oversized = format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"test\",\"params\":\"{}\"}}", "a".repeat(MAX_PAYLOAD_SIZE + 10));
    let res_over = McpJsonRpcRequest::from_json_str(&oversized);
    assert!(res_over.is_err());
    assert_eq!(res_over.unwrap_err().code, ERR_BOUNDS_EXCEEDED);

    // Result Envelope Error formatting
    let env: McpCoreResultEnvelope<String> = McpCoreResultEnvelope::error(ERR_PARSE_ERROR, "malformed framing");
    assert!(!env.ok);
    assert_eq!(env.status, "error");
    assert_eq!(env.error_code, Some(ERR_PARSE_ERROR));
}
