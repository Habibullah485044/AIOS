//! Incident Response Runbooks Security Policy Subsystem (T-03023..T-03032).
//!
//! Provides policy-driven governance over runbook start, confirmation gating,
//! substrate access, and security scanning budgets.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use crate::incident_runbook_data_model::{
    IncidentCategory, RunbookSpec, RunbookStep, RunbookTargetSubstrate,
};

pub const MAX_RUNBOOK_POLICY_BYTES: u64 = 64 * 1024;
pub const DEFAULT_MAX_STEP_TIMEOUT_SECS: u64 = 60;
pub const MAX_PERMISSIBLE_STEP_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_MAX_SCANNED_PORTS: usize = 10_000;
pub const DEFAULT_MAX_FILE_SCAN_DEPTH: usize = 16;
pub const DEFAULT_MAX_FILE_SCAN_BYTES: u64 = 16 * 1024 * 1024;

pub const RUNBOOKPOL_ERR_VALIDATION: &str = "RUNBOOKPOL_ERR_VALIDATION";
pub const RUNBOOKPOL_ERR_POLICY_VIOLATION: &str = "RUNBOOKPOL_ERR_POLICY_VIOLATION";
pub const RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED: &str = "RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED";
pub const RUNBOOKPOL_ERR_CATEGORY_DISALLOWED: &str = "RUNBOOKPOL_ERR_CATEGORY_DISALLOWED";
pub const RUNBOOKPOL_ERR_SUBSTRATE_DISALLOWED: &str = "RUNBOOKPOL_ERR_SUBSTRATE_DISALLOWED";
pub const RUNBOOKPOL_ERR_SCAN_BOUNDS: &str = "RUNBOOKPOL_ERR_SCAN_BOUNDS";
pub const RUNBOOKPOL_ERR_IO: &str = "RUNBOOKPOL_ERR_IO";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookEnforcementMode {
    Enforcing,
    Permissive,
    Disabled,
}

impl Default for RunbookEnforcementMode {
    fn default() -> Self {
        Self::Enforcing
    }
}

impl fmt::Display for RunbookEnforcementMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunbookEnforcementMode::Enforcing => write!(f, "enforcing"),
            RunbookEnforcementMode::Permissive => write!(f, "permissive"),
            RunbookEnforcementMode::Disabled => write!(f, "disabled"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookSecurityPolicy {
    pub version: String,
    #[serde(default)]
    pub mode: RunbookEnforcementMode,
    pub require_operator_confirmation_for_high_risk: bool,
    pub max_step_timeout_seconds: u64,
    pub max_active_sessions: u32,
    #[serde(default)]
    pub disallowed_categories: Vec<IncidentCategory>,
    #[serde(default)]
    pub disallowed_substrates: Vec<RunbookTargetSubstrate>,
    pub max_scanned_ports: usize,
    pub max_file_scan_depth: usize,
    pub max_file_scan_size_bytes: u64,
    pub require_pep_grant: bool,
}

impl Default for RunbookSecurityPolicy {
    fn default() -> Self {
        Self {
            version: "1.0.0".to_string(),
            mode: RunbookEnforcementMode::Enforcing,
            require_operator_confirmation_for_high_risk: true,
            max_step_timeout_seconds: DEFAULT_MAX_STEP_TIMEOUT_SECS,
            max_active_sessions: 100,
            disallowed_categories: Vec::new(),
            disallowed_substrates: Vec::new(),
            max_scanned_ports: DEFAULT_MAX_SCANNED_PORTS,
            max_file_scan_depth: DEFAULT_MAX_FILE_SCAN_DEPTH,
            max_file_scan_size_bytes: DEFAULT_MAX_FILE_SCAN_BYTES,
            require_pep_grant: true,
        }
    }
}

impl RunbookSecurityPolicy {
    pub fn evaluate_runbook_start(&self, spec: &RunbookSpec) -> Result<(), String> {
        if self.mode == RunbookEnforcementMode::Disabled {
            return Ok(());
        }

        if self.disallowed_categories.contains(&spec.category) {
            return Err(format!(
                "{}: Category {:?} is disallowed by security policy",
                RUNBOOKPOL_ERR_CATEGORY_DISALLOWED, spec.category
            ));
        }

        for step in &spec.steps {
            if self.disallowed_substrates.contains(&step.target) {
                return Err(format!(
                    "{}: Target substrate {:?} in step {} is disallowed by security policy",
                    RUNBOOKPOL_ERR_SUBSTRATE_DISALLOWED, step.target, step.id
                ));
            }
        }

        Ok(())
    }

    pub fn evaluate_step_advance(
        &self,
        step: &RunbookStep,
        operator_confirmed: bool,
    ) -> Result<(), String> {
        if self.mode == RunbookEnforcementMode::Disabled {
            return Ok(());
        }

        if self.require_operator_confirmation_for_high_risk
            && step.is_high_risk()
            && !operator_confirmed
        {
            return Err(format!(
                "{}: Step {} requires explicit operator confirmation under policy",
                RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED, step.id
            ));
        }

        if (step.timeout_seconds as u64) > self.max_step_timeout_seconds {
            return Err(format!(
                "{}: Step {} timeout {}s exceeds policy maximum {}s",
                RUNBOOKPOL_ERR_POLICY_VIOLATION, step.id, step.timeout_seconds, self.max_step_timeout_seconds
            ));
        }

        Ok(())
    }

    pub fn evaluate_scan_operation(
        &self,
        _action: &str,
        ports_count: usize,
        depth: usize,
    ) -> Result<(), String> {
        if self.mode == RunbookEnforcementMode::Disabled {
            return Ok(());
        }

        if ports_count > self.max_scanned_ports {
            return Err(format!(
                "{}: Scanned ports count {} exceeds policy limit {}",
                RUNBOOKPOL_ERR_SCAN_BOUNDS, ports_count, self.max_scanned_ports
            ));
        }

        if depth > self.max_file_scan_depth {
            return Err(format!(
                "{}: File scan depth {} exceeds policy limit {}",
                RUNBOOKPOL_ERR_SCAN_BOUNDS, depth, self.max_file_scan_depth
            ));
        }

        Ok(())
    }

    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let p = Path::new(path);
        if !p.exists() {
            return Err(format!("{}: Policy file '{}' does not exist", RUNBOOKPOL_ERR_IO, path));
        }

        let meta = fs::metadata(p).map_err(|e| format!("{}: Failed reading metadata: {}", RUNBOOKPOL_ERR_IO, e))?;
        if meta.len() > MAX_RUNBOOK_POLICY_BYTES {
            return Err(format!(
                "{}: Policy file size {} bytes exceeds maximum {} bytes",
                RUNBOOKPOL_ERR_IO, meta.len(), MAX_RUNBOOK_POLICY_BYTES
            ));
        }

        let content = fs::read_to_string(p).map_err(|e| format!("{}: Failed reading file: {}", RUNBOOKPOL_ERR_IO, e))?;
        serde_json::from_str(&content).map_err(|e| format!("{}: Failed parsing policy JSON: {}", RUNBOOKPOL_ERR_VALIDATION, e))
    }

    pub fn save_to_file(&self, path: &str) -> Result<(), String> {
        let json_str = serde_json::to_string_pretty(self)
            .map_err(|e| format!("{}: Failed serializing policy: {}", RUNBOOKPOL_ERR_VALIDATION, e))?;

        if json_str.len() as u64 > MAX_RUNBOOK_POLICY_BYTES {
            return Err(format!(
                "{}: Serialized policy size {} bytes exceeds maximum {}",
                RUNBOOKPOL_ERR_IO, json_str.len(), MAX_RUNBOOK_POLICY_BYTES
            ));
        }

        let mut file = File::create(path).map_err(|e| format!("{}: Failed creating file: {}", RUNBOOKPOL_ERR_IO, e))?;
        file.write_all(json_str.as_bytes())
            .map_err(|e| format!("{}: Failed writing policy: {}", RUNBOOKPOL_ERR_IO, e))?;
        file.flush()
            .map_err(|e| format!("{}: Failed flushing policy file: {}", RUNBOOKPOL_ERR_IO, e))?;
        Ok(())
    }
}
