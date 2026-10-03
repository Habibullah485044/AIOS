//! Threat Model Maintenance Core Service (THREATSVC1..THREATSVC5).
//!
//! Provides the runtime threat model repository, scoped queries,
//! state transitions, risk assessments, and atomic persistence.

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use crate::threat_model_data_model::*;

pub const DEFAULT_THREAT_MODEL_PATH: &str = "docs/threat_model.json";
pub const MAX_THREAT_ENTRIES_CAPACITY: usize = 512;
pub const MAX_THREAT_MODEL_STORE_SIZE: u64 = 1024 * 1024; // 1 MiB

pub const THREATSVC_ERR_NOT_FOUND: &str = "THREATSVC_ERR_NOT_FOUND";
pub const THREATSVC_ERR_CAPACITY_EXCEEDED: &str = "THREATSVC_ERR_CAPACITY_EXCEEDED";
pub const THREATSVC_ERR_FILE_SIZE: &str = "THREATSVC_ERR_FILE_SIZE";
pub const THREATSVC_ERR_PATH_TRAVERSAL: &str = "THREATSVC_ERR_PATH_TRAVERSAL";
pub const THREATSVC_ERR_IO: &str = "THREATSVC_ERR_IO";
pub const THREATSVC_ERR_PARSE: &str = "THREATSVC_ERR_PARSE";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatRiskAssessment {
    pub total_threats: usize,
    pub identified_count: usize,
    pub under_review_count: usize,
    pub mitigated_count: usize,
    pub accepted_count: usize,
    pub resolved_count: usize,
    pub critical_unmitigated_count: usize,
    pub overall_risk_score: u32,
    pub evaluated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatModelService {
    pub snapshot: ThreatModelSnapshot,
}

impl Default for ThreatModelService {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatModelService {
    pub fn new() -> Self {
        Self {
            snapshot: ThreatModelSnapshot::new("1.0.0"),
        }
    }

    pub fn validate_path(path: &Path) -> Result<PathBuf, String> {
        let p_str = path.to_string_lossy();
        if p_str.contains("..")
            || p_str.starts_with("\\\\")
            || p_str.starts_with("//")
            || p_str.chars().any(|c| c.is_control())
        {
            return Err(format!("{}: Path contains forbidden sequences: {}", THREATSVC_ERR_PATH_TRAVERSAL, p_str));
        }
        Ok(path.to_path_buf())
    }
}
