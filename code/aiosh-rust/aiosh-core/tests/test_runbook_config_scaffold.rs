//! Scaffold tests for Incident Response Runbooks configuration (T-03005).

use aiosh_core::runbook_config::{
    validate_config_path, ConfigSource, RunbookConfig, DEFAULT_CATALOG_PATH,
    DEFAULT_CONFIG_PATH, DEFAULT_MAX_ACTIVE_SESSIONS, DEFAULT_MAX_CATALOG_FILE_BYTES,
    DEFAULT_STEP_TIMEOUT_SECONDS, MAX_CONFIG_FILE_BYTES, RUNBOOKCONF_ERR_PATH_TRAVERSAL,
    resolve_runbook_config,
};

#[test]
fn test_constants_and_default_config() {
    assert_eq!(MAX_CONFIG_FILE_BYTES, 64 * 1024);
    assert_eq!(DEFAULT_CONFIG_PATH, "docs/runbook_config.json");
    assert_eq!(DEFAULT_CATALOG_PATH, "docs/runbook_catalog.json");

    let cfg = RunbookConfig::default();
    assert_eq!(cfg.max_active_sessions, DEFAULT_MAX_ACTIVE_SESSIONS);
    assert_eq!(cfg.max_catalog_file_bytes, DEFAULT_MAX_CATALOG_FILE_BYTES);
    assert_eq!(cfg.default_step_timeout_seconds, DEFAULT_STEP_TIMEOUT_SECONDS);
    assert!(cfg.require_operator_confirmation);
    assert_eq!(cfg.sources.get("catalog_path"), Some(&ConfigSource::Default));
}

#[test]
fn test_validate_config_path() {
    let p = validate_config_path("docs/runbook_catalog.json").unwrap();
    assert_eq!(p.to_str().unwrap(), "docs/runbook_catalog.json");

    let err = validate_config_path("../evil/path.json").unwrap_err();
    assert!(err.contains(RUNBOOKCONF_ERR_PATH_TRAVERSAL));
}

#[test]
fn test_resolve_scaffold() {
    let cfg = resolve_runbook_config(None).expect("resolve should succeed");
    assert_eq!(cfg.catalog_path, DEFAULT_CATALOG_PATH);
}
