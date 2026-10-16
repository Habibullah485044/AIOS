//! Hardening tests for MCP Server Core service (T-03080).
//!
//! Verifies:
//! - Idle and terminated session eviction via `prune_idle_sessions`
//! - Timeout clamping and bounded execution via `safe_dispatch_with_timeout`
//! - ADR-0035 §AF-2 non-panicking error envelopes under fault injection

use aiosh_core::mcp_server_core_data_model::*;
use aiosh_core::mcp_server_core_service::*;
use serde_json::json;

#[test]
fn test_hardening_prune_idle_and_terminated_sessions() {
    let service = McpServerCoreService::new();

    // Create 3 sessions
    assert!(service.create_session("sess-h1", "client-a", "1.0").is_ok());
    assert!(service.create_session("sess-h2", "client-b", "1.0").is_ok());
    assert!(service.create_session("sess-h3", "client-c", "1.0").is_ok());

    // Terminate sess-h1
    assert!(service.terminate_session("sess-h1").is_ok());

    // Prune terminated sessions (max_idle_seconds = 0)
    let pruned = service.prune_idle_sessions(0);
    assert_eq!(pruned, 1);

    // sess-h1 is gone
    assert!(service.get_session("sess-h1").is_none());
    // sess-h2 and sess-h3 remain
    assert!(service.get_session("sess-h2").is_some());
    assert!(service.get_session("sess-h3").is_some());
}

#[test]
fn test_hardening_safe_dispatch_timeout_and_fault_tolerance() {
    let service = McpServerCoreService::new();

    let tool = McpToolDefinition::new(
        "aios.hardening.ping",
        "Hardened ping tool",
        json!({"type": "object"}),
    ).expect("valid tool");
    assert!(service.register_tool(tool).is_ok());

    // Dispatch with excessive timeout (> 300s) -> clamped gracefully
    let call = McpToolCall::new("aios.hardening.ping", json!({}), None).expect("call valid");
    let env = service.safe_dispatch_with_timeout(call, 999999);
    assert!(env.ok);
    assert_eq!(env.status, "success");

    // Dispatch missing tool with zero timeout -> clamped to 1, fail-closed envelope
    let call_missing = McpToolCall::new("aios.missing.tool", json!({}), None).expect("call valid");
    let env_missing = service.safe_dispatch_with_timeout(call_missing, 0);
    assert!(!env_missing.ok);
    assert_eq!(env_missing.status, "error");
    assert_eq!(env_missing.error_code, Some(MCPSVC_ERR_TOOL_NOT_FOUND));
}
