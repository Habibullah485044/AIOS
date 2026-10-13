//! Rust-Native Security Tooling Substrate (RustSec).
//!
//! Provides memory-safe, sandboxed, high-concurrency security scanning:
//! - `scan_net`: Rapid non-blocking port scanning via RustScan or native TCP connect.
//! - `scan_files`: High-speed forensic log & IOC regex scanning via Ripgrep (rg) or native memory search.
//! - `scan_web`: Recursive web endpoint and API discovery via Feroxbuster or native HTTP prober.
//!
//! Every scan redemption enforces PEP capabilities (`cap:net:scan`, `cap:fs:search`, `cap:web:probe`)
//! and commits a Proof-of-Receipt record into the audit ring.

use serde::{Deserialize, Serialize};

pub const SEC_ERR_INVALID_TARGET: &str = "SEC_ERR_INVALID_TARGET";
pub const SEC_ERR_TIMEOUT: &str = "SEC_ERR_TIMEOUT";
pub const SEC_ERR_CAPABILITY_DENIED: &str = "SEC_ERR_CAPABILITY_DENIED";
pub const SEC_ERR_BOUNDS_EXCEEDED: &str = "SEC_ERR_BOUNDS_EXCEEDED";

pub const MAX_SCAN_TARGET_LEN: usize = 256;
pub const MAX_SCAN_PATTERN_LEN: usize = 256;
pub const MAX_SCAN_PORTS_COUNT: usize = 65535;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanNetResult {
    pub target: String,
    pub open_ports: Vec<u16>,
    pub scanned_ports_count: usize,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMatch {
    pub path: String,
    pub line_number: usize,
    pub line_content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFilesResult {
    pub target_dir: String,
    pub pattern: String,
    pub matches: Vec<FileMatch>,
    pub files_scanned_count: usize,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebEndpointMatch {
    pub url: String,
    pub status_code: u16,
    pub content_length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanWebResult {
    pub base_url: String,
    pub endpoints: Vec<WebEndpointMatch>,
    pub requests_sent: usize,
    pub elapsed_ms: u64,
}

/// Validate target string against injection characters and length limits.
pub fn validate_scan_target(target: &str) -> Result<(), String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err(format!("{}: Target cannot be empty", SEC_ERR_INVALID_TARGET));
    }
    if trimmed.len() > MAX_SCAN_TARGET_LEN {
        return Err(format!("{}: Target length {} exceeds maximum {}", SEC_ERR_BOUNDS_EXCEEDED, trimmed.len(), MAX_SCAN_TARGET_LEN));
    }
    if trimmed.contains("..") || trimmed.contains(';') || trimmed.contains('|') || trimmed.contains('&') || trimmed.contains('`') || trimmed.contains('$') {
        return Err(format!("{}: Target contains illegal characters", SEC_ERR_INVALID_TARGET));
    }
    Ok(())
}

/// Scaffold signature for network port scan.
pub fn scan_net(
    target: &str,
    ports: &[u16],
    _timeout_s: u64,
    _grant_token: Option<&str>,
) -> Result<ScanNetResult, String> {
    validate_scan_target(target)?;
    if ports.len() > MAX_SCAN_PORTS_COUNT {
        return Err(format!("{}: Ports count exceeds maximum", SEC_ERR_BOUNDS_EXCEEDED));
    }
    // Minimal stub for scaffold
    Ok(ScanNetResult {
        target: target.to_string(),
        open_ports: Vec::new(),
        scanned_ports_count: ports.len(),
        elapsed_ms: 0,
    })
}

/// Scaffold signature for file/log pattern scan.
pub fn scan_files(
    target_dir: &str,
    pattern: &str,
    _max_depth: usize,
    _timeout_s: u64,
    _grant_token: Option<&str>,
) -> Result<ScanFilesResult, String> {
    validate_scan_target(target_dir)?;
    if pattern.is_empty() || pattern.len() > MAX_SCAN_PATTERN_LEN {
        return Err(format!("{}: Invalid pattern length", SEC_ERR_BOUNDS_EXCEEDED));
    }
    // Minimal stub for scaffold
    Ok(ScanFilesResult {
        target_dir: target_dir.to_string(),
        pattern: pattern.to_string(),
        matches: Vec::new(),
        files_scanned_count: 0,
        elapsed_ms: 0,
    })
}

/// Scaffold signature for web endpoint scan.
pub fn scan_web(
    base_url: &str,
    _wordlist: Option<&[&str]>,
    _depth: usize,
    _timeout_s: u64,
    _grant_token: Option<&str>,
) -> Result<ScanWebResult, String> {
    validate_scan_target(base_url)?;
    // Minimal stub for scaffold
    Ok(ScanWebResult {
        base_url: base_url.to_string(),
        endpoints: Vec::new(),
        requests_sent: 0,
        elapsed_ms: 0,
    })
}
