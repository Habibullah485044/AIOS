//! Unit tests for Rust MCP Server Core Recovery & Validation Subsystem (MCPRECV-INV1..MCPRECV-INV5).

use aiosh_core::mcp_server_core_recovery::{
    recover_mcp_store, validate_store_path, McpRecoveryError,
    McpValidationReport,
};

use std::fs;
use std::path::Path;

#[test]
fn test_mcprecv_invariants_rust() {
    let rep_valid = McpValidationReport {
        store_path: "/tmp/store.json".into(),
        is_healthy: true,
        total_records: 3,
        valid_records: 3,
        invalid_records: 0,
        issues: vec![],
        validated_at_utc: "2026-10-18T22:00:00Z".into(),
    };
    assert!(rep_valid.validate_invariants().is_ok());

    let rep_invalid = McpValidationReport {
        store_path: "/tmp/store.json".into(),
        is_healthy: true,
        total_records: 4,
        valid_records: 2,
        invalid_records: 1,
        issues: vec![],
        validated_at_utc: "2026-10-18T22:00:00Z".into(),
    };
    assert!(rep_invalid.validate_invariants().is_err());
}

#[test]
fn test_mcprecv_path_traversal_rust() {
    assert!(validate_store_path(Path::new("normal/store.json")).is_ok());
    assert!(matches!(
        validate_store_path(Path::new("../escape.json")),
        Err(McpRecoveryError::InvalidPath(_))
    ));
    assert!(matches!(
        validate_store_path(Path::new("")),
        Err(McpRecoveryError::InvalidPath(_))
    ));
}

#[test]
fn test_mcprecv_token_gating_rust() {
    let temp_dir = std::env::temp_dir();
    let file = temp_dir.join("test_token_gate.json");
    let _ = fs::write(&file, "corrupt");

    let err = recover_mcp_store(&file, "");
    assert!(matches!(err, Err(McpRecoveryError::Unauthorized(_))));

    let err_ws = recover_mcp_store(&file, "   ");
    assert!(matches!(err_ws, Err(McpRecoveryError::Unauthorized(_))));

    let _ = fs::remove_file(&file);
}
