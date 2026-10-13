//! Implementation tests for Runbook configuration (T-03006).

use aiosh_core::runbook_config::*;

#[test]
fn test_resolve_default() {
    let resolved = resolve_runbook_config(None).expect("default resolution should succeed");
    assert_eq!(resolved.catalog_path, DEFAULT_CATALOG_PATH);
    assert_eq!(resolved.max_active_sessions, DEFAULT_MAX_ACTIVE_SESSIONS);
    assert_eq!(resolved.max_catalog_file_bytes, DEFAULT_MAX_CATALOG_FILE_BYTES);
    assert_eq!(resolved.default_step_timeout_seconds, DEFAULT_STEP_TIMEOUT_SECONDS);
    assert!(resolved.require_operator_confirmation);

    assert_eq!(resolved.sources.get("catalog_path"), Some(&ConfigSource::Default));
    assert_eq!(resolved.sources.get("max_active_sessions"), Some(&ConfigSource::Default));
}

#[test]
fn test_resolve_with_argument_overrides() {
    let overrides = RunbookConfigOverrides {
        config_path: None,
        catalog_path: Some("docs/custom_catalog.json".to_string()),
        max_active_sessions: Some(500),
        max_catalog_file_bytes: Some(2048 * 1024),
        default_step_timeout_seconds: Some(1800),
        require_operator_confirmation: Some(false),
    };

    let resolved = resolve_runbook_config(Some(&overrides)).expect("resolution with overrides should succeed");
    assert_eq!(resolved.catalog_path, "docs/custom_catalog.json");
    assert_eq!(resolved.max_active_sessions, 500);
    assert_eq!(resolved.max_catalog_file_bytes, 2048 * 1024);
    assert_eq!(resolved.default_step_timeout_seconds, 1800);
    assert!(!resolved.require_operator_confirmation);

    assert_eq!(resolved.sources.get("catalog_path"), Some(&ConfigSource::Argument));
    assert_eq!(resolved.sources.get("max_active_sessions"), Some(&ConfigSource::Argument));
}
