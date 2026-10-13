//! Scaffold tests for RustSec security tooling substrate and CLI (T-02985).

use aiosh_core::sec_tools::*;

#[test]
fn test_sec_tools_scaffold_target_validation() {
    assert!(validate_scan_target("127.0.0.1").is_ok());
    assert!(validate_scan_target("localhost").is_ok());
    assert!(validate_scan_target("/var/log/audit").is_ok());
    assert!(validate_scan_target("https://api.internal.local").is_ok());

    // Empty
    assert!(validate_scan_target("").is_err());

    // Path traversal
    assert!(validate_scan_target("../etc/shadow").is_err());

    // Injection metacharacters
    assert!(validate_scan_target("127.0.0.1; id").is_err());
    assert!(validate_scan_target("127.0.0.1 | bash").is_err());
    assert!(validate_scan_target("127.0.0.1 & nc").is_err());
    assert!(validate_scan_target("$(reboot)").is_err());
}

#[test]
fn test_sec_tools_scaffold_signatures() {
    let net_res = scan_net("127.0.0.1", &[80, 443], 5, None).unwrap();
    assert_eq!(net_res.target, "127.0.0.1");
    assert_eq!(net_res.scanned_ports_count, 2);

    let files_res = scan_files("/tmp", "CRITICAL_ALERT", 5, 5, None).unwrap();
    assert_eq!(files_res.target_dir, "/tmp");
    assert_eq!(files_res.pattern, "CRITICAL_ALERT");

    let web_res = scan_web("http://127.0.0.1:8080", None, 2, 5, None).unwrap();
    assert_eq!(web_res.base_url, "http://127.0.0.1:8080");
}
