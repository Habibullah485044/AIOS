//! Unit tests for RustSec security scanning tooling (T-02987).

use aiosh_core::sec_tools::*;
use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_sec_tools_target_validation() {
    // Valid targets
    assert!(validate_scan_target("127.0.0.1").is_ok());
    assert!(validate_scan_target("10.0.0.1:8080").is_ok());
    assert!(validate_scan_target("localhost").is_ok());
    assert!(validate_scan_target("/var/log/audit.log").is_ok());
    assert!(validate_scan_target("http://127.0.0.1:8000").is_ok());
    assert!(validate_scan_target("https://api.github.com").is_ok());

    // Empty or whitespace
    assert!(validate_scan_target("").is_err());
    assert!(validate_scan_target("   ").is_err());

    // Path traversal
    assert!(validate_scan_target("../../../etc/passwd").is_err());
    assert!(validate_scan_target("/var/log/../etc").is_err());

    // Shell metacharacters / command injection
    assert!(validate_scan_target("127.0.0.1; rm -rf").is_err());
    assert!(validate_scan_target("127.0.0.1 | cat").is_err());
    assert!(validate_scan_target("127.0.0.1 & echo").is_err());
    assert!(validate_scan_target("`id`").is_err());
    assert!(validate_scan_target("$(whoami)").is_err());

    // Bounds exceeded
    let oversized = "A".repeat(MAX_SCAN_TARGET_LEN + 1);
    assert!(validate_scan_target(&oversized).is_err());
}

#[test]
fn test_sec_tools_scan_net_bounds_and_execution() {
    // Valid target with single port
    let res = scan_net("127.0.0.1", &[65530], 2, None).unwrap();
    assert_eq!(res.target, "127.0.0.1");
    assert_eq!(res.scanned_ports_count, 1);

    // Invalid target
    assert!(scan_net("; echo fail", &[80], 2, None).is_err());
}

#[test]
fn test_sec_tools_scan_files_matching() {
    let dir = tempdir().unwrap();
    let file1_path = dir.path().join("auth.log");
    let mut file1 = File::create(&file1_path).unwrap();
    writeln!(file1, "Accepted password for root from 192.168.1.1").unwrap();
    writeln!(file1, "Failed password for admin from 10.0.0.99").unwrap();
    writeln!(file1, "SESSION_CLOSED: uid=0").unwrap();

    let file2_path = dir.path().join("other.txt");
    let mut file2 = File::create(&file2_path).unwrap();
    writeln!(file2, "Nothing interesting here").unwrap();

    // Scan for pattern "Failed password"
    let res = scan_files(dir.path().to_str().unwrap(), "Failed password", 3, 5, None).unwrap();
    assert_eq!(res.matches.len(), 1);
    assert_eq!(res.matches[0].line_number, 2);
    assert!(res.matches[0].line_content.contains("Failed password for admin"));
    assert_eq!(res.files_scanned_count, 2);

    // Non-existent directory
    let bad_dir = dir.path().join("non_existent_folder");
    assert!(scan_files(bad_dir.to_str().unwrap(), "test", 3, 5, None).is_err());

    // Empty pattern
    assert!(scan_files(dir.path().to_str().unwrap(), "", 3, 5, None).is_err());
}

#[test]
fn test_sec_tools_scan_web_validation() {
    // Missing scheme
    assert!(scan_web("example.com", None, 1, 2, None).is_err());
    assert!(scan_web("ftp://example.com", None, 1, 2, None).is_err());

    // Valid scheme
    let res = scan_web("http://127.0.0.1:59999", Some(&["/test"]), 1, 1, None).unwrap();
    assert_eq!(res.base_url, "http://127.0.0.1:59999");
    assert_eq!(res.requests_sent, 1);
}
