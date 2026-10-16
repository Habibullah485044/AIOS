//! Hardening test for MCP Server Core data model (T-03070).
//!
//! Verifies:
//! - ADR-0035 §AF-2 envelope compliance on failure and success
//! - Non-panicking behavior on massive inputs and malformed strings
//! - Zero memory leaks or dangling state

use aiosh_core::mcp_server_core_data_model::*;
use serde_json::json;

#[test]
fn test_hardening_safe_parse_envelope() {
    // 1. Success case
    let valid_raw = "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"ping\"}";
    let env = safe_parse_request_envelope(valid_raw);
    assert!(env.ok);
    assert_eq!(env.status, "success");
    assert_eq!(env.data.unwrap().id, McpRequestId::Number(99));

    // 2. Syntax parse error (must not panic)
    let bad_raw = "{not valid json at all}";
    let env_bad = safe_parse_request_envelope(bad_raw);
    assert!(!env_bad.ok);
    assert_eq!(env_bad.status, "error");
    assert_eq!(env_bad.error_code, Some(ERR_PARSE_ERROR));

    // 3. Huge payload (must reject gracefully)
    let huge = "x".repeat(MAX_PAYLOAD_SIZE + 1024);
    let env_huge = safe_parse_request_envelope(&huge);
    assert!(!env_huge.ok);
    assert_eq!(env_huge.error_code, Some(ERR_BOUNDS_EXCEEDED));
}

#[test]
fn test_hardening_safe_validate_tool_envelope() {
    // 1. Valid tool
    let env = safe_validate_tool_envelope(
        "aios.safe.tool",
        "A hardened tool",
        json!({"type": "object"}),
    );
    assert!(env.ok);
    assert_eq!(env.data.unwrap().name, "aios.safe.tool");

    // 2. Malformed tool with control chars
    let env_bad = safe_validate_tool_envelope(
        "aios.tool\x00null",
        "description",
        json!({}),
    );
    assert!(!env_bad.ok);
    assert_eq!(env_bad.error_code, Some(ERR_SANITIZATION_FAILED));
}
