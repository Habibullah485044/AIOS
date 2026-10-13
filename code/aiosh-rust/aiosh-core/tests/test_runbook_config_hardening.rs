//! Hardening tests for Incident Response Runbooks configuration (T-03010).

use aiosh_core::runbook_config::*;
use std::fs::File;
use std::io::Write;

#[test]
fn test_safe_resolve_runbook_config_success() {
    let safe_res = safe_resolve_runbook_config(None);
    assert!(safe_res.ok);
    assert!(safe_res.error_code.is_none());
    assert!(safe_res.error.is_none());
    assert_eq!(safe_res.config.catalog_path, DEFAULT_CATALOG_PATH);
}

#[test]
fn test_safe_resolve_runbook_config_failure_envelope() {
    let overrides = RunbookConfigOverrides {
        config_path: Some("../evil/traversal.json".to_string()),
        ..Default::default()
    };

    let safe_res = safe_resolve_runbook_config(Some(&overrides));
    assert!(!safe_res.ok);
    assert_eq!(safe_res.error_code, Some(RUNBOOKCONF_ERR_PATH_TRAVERSAL.to_string()));
    assert!(safe_res.error.unwrap().contains("strictly prohibited"));
    assert_eq!(safe_res.config.catalog_path, DEFAULT_CATALOG_PATH);
}

#[test]
fn test_safe_resolve_runbook_config_oversized_file() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let huge_cfg_path = temp_dir.path().join("huge_config.json");
    {
        let mut f = File::create(&huge_cfg_path).expect("create huge file");
        let payload = vec![b'A'; (MAX_CONFIG_FILE_BYTES + 100) as usize];
        f.write_all(&payload).expect("write huge payload");
    }

    let overrides = RunbookConfigOverrides {
        config_path: Some(huge_cfg_path.to_str().unwrap().to_string()),
        ..Default::default()
    };

    let safe_res = safe_resolve_runbook_config(Some(&overrides));
    assert!(!safe_res.ok);
    assert_eq!(safe_res.error_code, Some(RUNBOOKCONF_ERR_FILE_SIZE.to_string()));
    assert!(safe_res.error.unwrap().contains("exceeds maximum"));
}
