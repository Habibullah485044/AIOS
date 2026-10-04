//! Compliance Mapping Core Service (COMPLYSVC1..COMPLYSVC5).
//!
//! Provides the runtime compliance mapping engine, persistence,
//! framework-scoped posture assessment, and PEP coverage auditing.

use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::canonical::utcnow_iso;
use crate::compliance_data_model::*;

pub const DEFAULT_COMPLIANCE_MAP_PATH: &str = "docs/compliance_map.json";
pub const MAX_COMPLIANCE_STORE_SIZE: u64 = 1024 * 1024; // 1 MiB

pub const COMPLIANCESVC_ERR_NOT_FOUND: &str = "COMPLIANCESVC_ERR_NOT_FOUND";
pub const COMPLIANCESVC_ERR_CAPACITY_EXCEEDED: &str = "COMPLIANCESVC_ERR_CAPACITY_EXCEEDED";
pub const COMPLIANCESVC_ERR_FILE_SIZE: &str = "COMPLIANCESVC_ERR_FILE_SIZE";
pub const COMPLIANCESVC_ERR_PATH_TRAVERSAL: &str = "COMPLIANCESVC_ERR_PATH_TRAVERSAL";
pub const COMPLIANCESVC_ERR_IO: &str = "COMPLIANCESVC_ERR_IO";
pub const COMPLIANCESVC_ERR_PARSE: &str = "COMPLIANCESVC_ERR_PARSE";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceAssessmentReport {
    pub total_mappings: usize,
    pub compliant_count: usize,
    pub partially_compliant_count: usize,
    pub non_compliant_count: usize,
    pub not_applicable_count: usize,
    pub compliance_percentage: f64,
    pub gap_control_ids: Vec<String>,
    pub evaluated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceService {
    pub snapshot: ComplianceCatalogSnapshot,
}

impl Default for ComplianceService {
    fn default() -> Self {
        Self::new()
    }
}

impl ComplianceService {
    pub fn new() -> Self {
        Self {
            snapshot: ComplianceCatalogSnapshot::new("1.0.0"),
        }
    }

    pub fn with_canonical_baseline() -> Self {
        Self {
            snapshot: ComplianceCatalogSnapshot::canonical_baseline(),
        }
    }

    pub fn validate_path(path: &Path) -> Result<PathBuf, String> {
        let p_str = path.to_string_lossy();
        if p_str.trim().is_empty() {
            return Err(format!("{}: Path cannot be empty", COMPLIANCESVC_ERR_PATH_TRAVERSAL));
        }
        if p_str.contains("..")
            || p_str.starts_with("\\\\")
            || p_str.starts_with("//")
            || p_str.chars().any(|c| c.is_control())
        {
            return Err(format!("{}: Path contains forbidden sequences: {}", COMPLIANCESVC_ERR_PATH_TRAVERSAL, p_str));
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            return Err(format!("{}: File must have .json extension: {}", COMPLIANCESVC_ERR_PATH_TRAVERSAL, p_str));
        }
        if path.components().count() > 16 {
            return Err(format!("{}: Path depth exceeds maximum allowed of 16", COMPLIANCESVC_ERR_PATH_TRAVERSAL));
        }
        if path.exists() {
            if let Ok(meta) = fs::symlink_metadata(path) {
                if meta.file_type().is_symlink() {
                    return Err(format!("{}: Symlinks are forbidden for compliance storage: {}", COMPLIANCESVC_ERR_PATH_TRAVERSAL, p_str));
                }
            }
        }
        Ok(path.to_path_buf())
    }

    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let valid_path = Self::validate_path(path)?;
        if !valid_path.exists() {
            return Err(format!("{}: Compliance store file not found: {}", COMPLIANCESVC_ERR_IO, valid_path.display()));
        }

        let meta = fs::metadata(&valid_path)
            .map_err(|e| format!("{}: Failed reading metadata: {}", COMPLIANCESVC_ERR_IO, e))?;
        if meta.len() > MAX_COMPLIANCE_STORE_SIZE {
            return Err(format!(
                "{}: File size {} exceeds maximum allowed {}",
                COMPLIANCESVC_ERR_FILE_SIZE,
                meta.len(),
                MAX_COMPLIANCE_STORE_SIZE
            ));
        }

        let content = fs::read_to_string(&valid_path)
            .map_err(|e| format!("{}: Failed reading file: {}", COMPLIANCESVC_ERR_IO, e))?;
        let snapshot: ComplianceCatalogSnapshot = serde_json::from_str(&content)
            .map_err(|e| format!("{}: Failed deserializing JSON: {}", COMPLIANCESVC_ERR_PARSE, e))?;

        Ok(Self { snapshot })
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), String> {
        let valid_path = Self::validate_path(path)?;
        let parent = valid_path.parent().unwrap_or_else(|| Path::new("."));
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("{}: Failed creating parent directory: {}", COMPLIANCESVC_ERR_IO, e))?;
        }

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let pid = std::process::id();
        let fname = valid_path.file_name().and_then(|n| n.to_str()).unwrap_or("compliance");
        let tmp_path = parent.join(format!(".{}.tmp.{}.{}", fname, pid, nanos));

        let json_str = serde_json::to_string_pretty(&self.snapshot)
            .map_err(|e| format!("{}: Serialization error: {}", COMPLIANCESVC_ERR_IO, e))?;

        if let Err(e) = fs::write(&tmp_path, json_str) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("{}: Failed writing tmp file: {}", COMPLIANCESVC_ERR_IO, e));
        }

        if let Err(e) = fs::rename(&tmp_path, &valid_path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("{}: Failed atomic rename: {}", COMPLIANCESVC_ERR_IO, e));
        }

        Ok(())
    }

    pub fn register_mapping(&mut self, entry: ComplianceMappingEntry) -> Result<(), String> {
        self.snapshot.add_mapping(entry)
    }

    pub fn get_mapping(&self, id: &str) -> Option<&ComplianceMappingEntry> {
        self.snapshot.get_mapping(id)
    }

    pub fn update_status(&mut self, id: &str, status: ComplianceStatus, reason: &str) -> Result<(), String> {
        let entry = self.snapshot.get_mapping_mut(id)
            .ok_or_else(|| format!("{}: Mapping ID '{}' not found", COMPLIANCESVC_ERR_NOT_FOUND, id))?;
        entry.transition_to(status, reason)
    }

    pub fn assess_framework(&self, framework: Option<ComplianceFramework>) -> ComplianceAssessmentReport {
        let targets: Vec<&ComplianceMappingEntry> = match framework {
            Some(fw) => self.snapshot.find_by_framework(fw),
            None => self.snapshot.mappings.iter().collect(),
        };

        let mut compliant = 0;
        let mut partially = 0;
        let mut non_compliant = 0;
        let mut not_applicable = 0;
        let mut gaps = Vec::new();

        for m in &targets {
            match m.status {
                ComplianceStatus::Compliant => compliant += 1,
                ComplianceStatus::PartiallyCompliant => {
                    partially += 1;
                    gaps.push(m.control_id.clone());
                }
                ComplianceStatus::NonCompliant => {
                    non_compliant += 1;
                    gaps.push(m.control_id.clone());
                }
                ComplianceStatus::NotApplicable => not_applicable += 1,
            }
        }

        let total = targets.len();
        let percentage = if total == 0 {
            100.0
        } else {
            (compliant as f64 / total as f64) * 100.0
        };

        ComplianceAssessmentReport {
            total_mappings: total,
            compliant_count: compliant,
            partially_compliant_count: partially,
            non_compliant_count: non_compliant,
            not_applicable_count: not_applicable,
            compliance_percentage: percentage,
            gap_control_ids: gaps,
            evaluated_at: utcnow_iso(),
        }
    }

    pub fn verify_pep_coverage(&self, gate_id: &str) -> bool {
        self.snapshot.mappings.iter().any(|m| {
            m.target_type == SubstrateTargetType::PepGate
                && m.target_ref == gate_id
                && (m.status == ComplianceStatus::Compliant || m.status == ComplianceStatus::PartiallyCompliant)
        })
    }
}
