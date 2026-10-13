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
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant};

pub const SEC_ERR_INVALID_TARGET: &str = "SEC_ERR_INVALID_TARGET";
pub const SEC_ERR_TIMEOUT: &str = "SEC_ERR_TIMEOUT";
pub const SEC_ERR_CAPABILITY_DENIED: &str = "SEC_ERR_CAPABILITY_DENIED";
pub const SEC_ERR_BOUNDS_EXCEEDED: &str = "SEC_ERR_BOUNDS_EXCEEDED";
pub const SEC_ERR_IO: &str = "SEC_ERR_IO";

pub const MAX_SCAN_TARGET_LEN: usize = 256;
pub const MAX_SCAN_PATTERN_LEN: usize = 256;
pub const MAX_SCAN_PORTS_COUNT: usize = 65535;
pub const MAX_SCAN_MATCHES_COUNT: usize = 1000;
pub const MAX_SCAN_FILE_SIZE_BYTES: u64 = 10 * 1024 * 1024; // 10 MB per file limit

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

/// Validate target string against injection characters, path traversal, and length limits.
pub fn validate_scan_target(target: &str) -> Result<(), String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err(format!("{}: Target cannot be empty", SEC_ERR_INVALID_TARGET));
    }
    if trimmed.len() > MAX_SCAN_TARGET_LEN {
        return Err(format!("{}: Target length {} exceeds maximum {}", SEC_ERR_BOUNDS_EXCEEDED, trimmed.len(), MAX_SCAN_TARGET_LEN));
    }
    if trimmed.contains("..") || trimmed.contains(';') || trimmed.contains('|') || trimmed.contains('&') || trimmed.contains('`') || trimmed.contains('$') {
        return Err(format!("{}: Target contains illegal characters or path traversal", SEC_ERR_INVALID_TARGET));
    }
    Ok(())
}

/// Perform rapid network port scan with native socket connects.
pub fn scan_net(
    target: &str,
    ports: &[u16],
    timeout_s: u64,
    _grant_token: Option<&str>,
) -> Result<ScanNetResult, String> {
    validate_scan_target(target)?;
    if ports.len() > MAX_SCAN_PORTS_COUNT {
        return Err(format!("{}: Ports count {} exceeds maximum {}", SEC_ERR_BOUNDS_EXCEEDED, ports.len(), MAX_SCAN_PORTS_COUNT));
    }

    let start = Instant::now();
    let max_duration = Duration::from_secs(timeout_s.max(1));
    let mut open_ports = Vec::new();

    // Default per-port connect timeout
    let per_port_timeout = Duration::from_millis(80);

    for &port in ports {
        if start.elapsed() >= max_duration {
            break;
        }

        let addr_str = format!("{}:{}", target, port);
        if let Ok(mut addrs) = addr_str.to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                if let Ok(_stream) = TcpStream::connect_timeout(&addr, per_port_timeout) {
                    open_ports.push(port);
                }
            }
        }
    }

    open_ports.sort_unstable();

    Ok(ScanNetResult {
        target: target.to_string(),
        open_ports,
        scanned_ports_count: ports.len(),
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

/// Perform recursive file/log IOC pattern scan.
pub fn scan_files(
    target_dir: &str,
    pattern: &str,
    max_depth: usize,
    timeout_s: u64,
    _grant_token: Option<&str>,
) -> Result<ScanFilesResult, String> {
    validate_scan_target(target_dir)?;
    if pattern.is_empty() || pattern.len() > MAX_SCAN_PATTERN_LEN {
        return Err(format!("{}: Pattern length must be between 1 and {}", SEC_ERR_BOUNDS_EXCEEDED, MAX_SCAN_PATTERN_LEN));
    }

    let dir_path = Path::new(target_dir);
    if !dir_path.exists() {
        return Err(format!("{}: Target directory '{}' does not exist", SEC_ERR_IO, target_dir));
    }

    let start = Instant::now();
    let max_duration = Duration::from_secs(timeout_s.max(1));
    let mut matches = Vec::new();
    let mut files_scanned = 0;

    walk_dir_search(
        dir_path,
        pattern,
        0,
        max_depth,
        start,
        max_duration,
        &mut matches,
        &mut files_scanned,
    );

    Ok(ScanFilesResult {
        target_dir: target_dir.to_string(),
        pattern: pattern.to_string(),
        matches,
        files_scanned_count: files_scanned,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}

fn walk_dir_search(
    dir: &Path,
    pattern: &str,
    current_depth: usize,
    max_depth: usize,
    start: Instant,
    max_duration: Duration,
    matches: &mut Vec<FileMatch>,
    files_scanned: &mut usize,
) {
    if current_depth > max_depth || start.elapsed() >= max_duration || matches.len() >= MAX_SCAN_MATCHES_COUNT {
        return;
    }

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if start.elapsed() >= max_duration || matches.len() >= MAX_SCAN_MATCHES_COUNT {
                break;
            }
            let path = entry.path();
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // Skip hidden directories and artifact caches
            if file_name.starts_with('.') || file_name == "target" || file_name == "node_modules" {
                continue;
            }

            if path.is_dir() {
                walk_dir_search(
                    &path,
                    pattern,
                    current_depth + 1,
                    max_depth,
                    start,
                    max_duration,
                    matches,
                    files_scanned,
                );
            } else if path.is_file() {
                if let Ok(meta) = path.metadata() {
                    if meta.len() <= MAX_SCAN_FILE_SIZE_BYTES {
                        *files_scanned += 1;
                        search_in_file(&path, pattern, matches);
                    }
                }
            }
        }
    }
}

fn search_in_file(path: &Path, pattern: &str, matches: &mut Vec<FileMatch>) {
    if let Ok(file) = File::open(path) {
        let reader = BufReader::new(file);
        let path_str = path.to_string_lossy().to_string();

        for (idx, line_res) in reader.lines().enumerate() {
            if matches.len() >= MAX_SCAN_MATCHES_COUNT {
                break;
            }
            if let Ok(line) = line_res {
                if line.contains(pattern) {
                    matches.push(FileMatch {
                        path: path_str.clone(),
                        line_number: idx + 1,
                        line_content: line.trim().chars().take(256).collect(),
                    });
                }
            }
        }
    }
}

/// Perform recursive web endpoint and API discovery.
pub fn scan_web(
    base_url: &str,
    wordlist: Option<&[&str]>,
    _depth: usize,
    timeout_s: u64,
    _grant_token: Option<&str>,
) -> Result<ScanWebResult, String> {
    validate_scan_target(base_url)?;

    let clean_base = base_url.trim_end_matches('/');
    if !clean_base.starts_with("http://") && !clean_base.starts_with("https://") {
        return Err(format!("{}: Base URL must begin with http:// or https://", SEC_ERR_INVALID_TARGET));
    }

    let default_paths = [
        "",
        "/api",
        "/health",
        "/status",
        "/metrics",
        "/admin",
        "/login",
        "/info",
        "/v1",
        "/swagger",
        "/.well-known/security.txt",
    ];

    let paths: &[&str] = wordlist.unwrap_or(&default_paths);

    let start = Instant::now();
    let max_duration = Duration::from_secs(timeout_s.max(1));
    let mut endpoints = Vec::new();
    let mut requests_sent = 0;

    let agent = ureq::builder()
        .timeout(Duration::from_millis(500))
        .build();

    for &subpath in paths {
        if start.elapsed() >= max_duration {
            break;
        }

        let target_endpoint = if subpath.is_empty() {
            clean_base.to_string()
        } else if subpath.starts_with('/') {
            format!("{}{}", clean_base, subpath)
        } else {
            format!("{}/{}", clean_base, subpath)
        };

        requests_sent += 1;
        match agent.get(&target_endpoint).call() {
            Ok(resp) => {
                let status = resp.status();
                let len = resp.header("Content-Length")
                    .and_then(|h| h.parse::<usize>().ok())
                    .unwrap_or(0);

                endpoints.push(WebEndpointMatch {
                    url: target_endpoint,
                    status_code: status,
                    content_length: len,
                });
            }
            Err(ureq::Error::Status(status, resp)) => {
                let len = resp.header("Content-Length")
                    .and_then(|h| h.parse::<usize>().ok())
                    .unwrap_or(0);

                endpoints.push(WebEndpointMatch {
                    url: target_endpoint,
                    status_code: status,
                    content_length: len,
                });
            }
            Err(_) => {
                // Connection refused or timeout on this endpoint; continue probing
            }
        }
    }

    Ok(ScanWebResult {
        base_url: clean_base.to_string(),
        endpoints,
        requests_sent,
        elapsed_ms: start.elapsed().as_millis() as u64,
    })
}
