//! Comprehensive unit tests for Incident Response Runbooks configuration (T-03007).

use aiosh_core::runbook_config::*;
use std::fs::File;
use std::io::Write;

#[test]
fn test_unit_validate_config_path_boundaries() {
    // Valid relative path
    assert!(validate_config_path("docs/runbook_catalog.json").is_ok());

    // Empty path fails
    let err = validate_config_path("").unwrap_err();
    assert!(err.contains(RUNBOOKCONF_ERR_VALIDATION));

    // Whitespace only fails
    let err2 = validate_config_path("   ").unwrap_err();
    assert!(err2.contains(RUNBOOKCONF_ERR_VALIDATION));

    // Path traversal strictly prohibited
    let err3 = validate_config_path("../evil/path.json").unwrap_err();
    assert!(err3.contains(RUNBOOKCONF_ERR_PATH_TRAVERSAL));

    let err4 = validate_config_path("foo/bar/../../baz").unwrap_err();
    assert!(err4.contains(RUNBOOKCONF_ERR_PATH_TRAVERSAL));

    // Length limit > 1024
    let long_path = "a".repeat(1025);
    let err5 = validate_config_path(&long_path).unwrap_err();
    assert!(err5.contains(RUNBOOKCONF_ERR_BOUNDS));
}

#[test]
fn test_unit_hygiene_predicate() {
    assert!(hygiene_ok("valid/path/config.json"));
    assert!(!hygiene_ok(""));
    assert!(!hygiene_ok("   "));
    assert!(!hygiene_ok("../traversal"));
    assert!(!hygiene_ok("bad\x00character"));
    assert!(!hygiene_ok("bad\x1fcharacter"));
}

#[test]
fn test_unit_clamping_boundaries() {
    // Min bound clamping
    let low_overrides = RunbookConfigOverrides {
        config_path: None,
        catalog_path: None,
        max_active_sessions: Some(0), // below min 1
        max_catalog_file_bytes: Some(10), // below min 4096
        default_step_timeout_seconds: Some(0), // below min 1
        require_operator_confirmation: None,
    };
    let res_low = resolve_runbook_config(Some(&low_overrides)).expect("resolution should succeed");
    assert_eq!(res_low.max_active_sessions, MIN_MAX_ACTIVE_SESSIONS);
    assert_eq!(res_low.max_catalog_file_bytes, MIN_MAX_CATALOG_FILE_BYTES);
    assert_eq!(res_low.default_step_timeout_seconds, MIN_STEP_TIMEOUT_SECONDS);

    // Max bound clamping
    let high_overrides = RunbookConfigOverrides {
        config_path: None,
        catalog_path: None,
        max_active_sessions: Some(50000), // above max 10000
        max_catalog_file_bytes: Some(50 * 1024 * 1024), // above max 16 MiB
        default_step_timeout_seconds: Some(200000), // above max 86400
        require_operator_confirmation: None,
    };
    let res_high = resolve_runbook_config(Some(&high_overrides)).expect("resolution should succeed");
    assert_eq!(res_high.max_active_sessions, MAX_MAX_ACTIVE_SESSIONS);
    assert_eq!(res_high.max_catalog_file_bytes, MAX_MAX_CATALOG_FILE_BYTES);
    assert_eq!(res_high.default_step_timeout_seconds, MAX_STEP_TIMEOUT_SECONDS);
}

#[test]
fn test_unit_file_resolution_and_oversize_error() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let valid_cfg_path = temp_dir.path().join("valid_config.json");
    {
        let mut f = File::create(&valid_cfg_path).expect("create file");
        write!(
            f,
            r#"{{"max_active_sessions": 250, "default_step_timeout_seconds": 600, "require_operator_confirmation": false}}"#
        )
        .expect("write config");
    }

    let overrides = RunbookConfigOverrides {
        config_path: Some(valid_cfg_path.to_str().unwrap().to_string()),
        ..Default::default()
    };
    let res = resolve_runbook_config(Some(&overrides)).expect("valid file should resolve");
    assert_eq!(res.max_active_sessions, 250);
    assert_eq!(res.default_step_timeout_seconds, 600);
    assert!(!res.require_operator_confirmation);
    assert_eq!(res.sources.get("max_active_sessions"), Some(&ConfigSource::File));
    assert_eq!(res.sources.get("require_operator_confirmation"), Some(&ConfigSource::File));

    // Oversized config file (> 64 KiB)
    let huge_cfg_path = temp_dir.path().join("huge_config.json");
    {
        let mut f = File::create(&huge_cfg_path).expect("create huge file");
        let payload = vec![b' '; (MAX_CONFIG_FILE_BYTES + 10) as usize];
        f.write_all(&payload).expect("write huge payload");
    }

    let huge_overrides = RunbookConfigOverrides {
        config_path: Some(huge_cfg_path.to_str().unwrap().to_string()),
        ..Default::default()
    };
    let err = resolve_runbook_config(Some(&huge_overrides)).unwrap_err();
    assert!(err.contains(RUNBOOKCONF_ERR_FILE_SIZE));
}

#[test]
fn test_unit_corrupted_json_fails_closed() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let corrupt_path = temp_dir.path().join("corrupt.json");
    {
        let mut f = File::create(&corrupt_path).expect("create corrupt file");
        write!(f, "{{ malformed json: true, ").expect("write corrupt payload");
    }

    let overrides = RunbookConfigOverrides {
        config_path: Some(corrupt_path.to_str().unwrap().to_string()),
        ..Default::default()
    };
    let err = resolve_runbook_config(Some(&overrides)).unwrap_err();
    assert!(err.contains(RUNBOOKCONF_ERR_PARSE));
}
