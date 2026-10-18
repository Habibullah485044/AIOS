//! Unit tests for MCP Server Core configuration subsystem (T-03107).

use aiosh_core::mcp_server_core_config::*;

#[test]
fn test_unit_case1_valid_config() {
    let cfg = McpServerCoreConfig::default();
    assert!(cfg.validate().is_ok());

    let json_str = cfg.to_json_str().unwrap();
    let restored = McpServerCoreConfig::from_json_str(&json_str).unwrap();
    assert_eq!(restored, cfg);
}

#[test]
fn test_unit_case2_invalid_config() {
    // Empty store path
    let mut cfg = McpServerCoreConfig::default();
    cfg.store_path = std::path::PathBuf::from("");
    assert!(cfg.validate().is_err());

    // Traversal
    let mut cfg2 = McpServerCoreConfig::default();
    cfg2.store_path = std::path::PathBuf::from("../../evil");
    assert!(cfg2.validate().is_err());

    // NUL byte
    let mut cfg3 = McpServerCoreConfig::default();
    cfg3.store_path = std::path::PathBuf::from("bad\0path");
    assert!(cfg3.validate().is_err());
}

#[test]
fn test_unit_case3_boundary_values() {
    // Min bounds
    let mut min_cfg = McpServerCoreConfig::default();
    min_cfg.max_active_sessions = MIN_ACTIVE_SESSIONS;
    min_cfg.session_idle_timeout_seconds = MIN_IDLE_TIMEOUT;
    min_cfg.default_execution_timeout_seconds = MIN_EXECUTION_TIMEOUT;
    min_cfg.max_arguments_size_bytes = MIN_ARGUMENTS_SIZE;
    min_cfg.max_tools_count = MIN_TOOLS_COUNT;
    assert!(min_cfg.validate().is_ok());

    // Max bounds
    let mut max_cfg = McpServerCoreConfig::default();
    max_cfg.max_active_sessions = MAX_ALLOWED_ACTIVE_SESSIONS;
    max_cfg.session_idle_timeout_seconds = MAX_ALLOWED_IDLE_TIMEOUT;
    max_cfg.default_execution_timeout_seconds = MAX_ALLOWED_EXECUTION_TIMEOUT;
    max_cfg.max_arguments_size_bytes = MAX_ALLOWED_ARGUMENTS_SIZE;
    max_cfg.max_tools_count = MAX_ALLOWED_TOOLS_COUNT;
    assert!(max_cfg.validate().is_ok());

    // Beyond max bounds
    let mut invalid = McpServerCoreConfig::default();
    invalid.max_active_sessions = MAX_ALLOWED_ACTIVE_SESSIONS + 1;
    assert!(invalid.validate().is_err());
}

#[test]
fn test_unit_case4_primary_failure_modes() {
    // Missing file
    assert!(McpServerCoreConfig::load_from_file("nonexistent_path_xyz.json").is_err());

    // Oversized content
    let huge = " ".repeat((MAX_CONFIG_FILE_BYTES + 10) as usize);
    assert!(McpServerCoreConfig::from_json_str(&huge).is_err());
}
