//! Incident Response Runbooks Security Policy Subsystem (T-03023..T-03032).
//!
//! Provides policy-driven governance over runbook start, confirmation gating,
//! substrate access, and security scanning budgets.

use serde::{Deserialize, Serialize};
use std::fmt;

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
    pub fn evaluate_runbook_start(&self, _spec: &RunbookSpec) -> Result<(), String> {
        unimplemented!("evaluate_runbook_start scaffold - pending T-03026")
    }

    pub fn evaluate_step_advance(
        &self,
        _step: &RunbookStep,
        _operator_confirmed: bool,
    ) -> Result<(), String> {
        unimplemented!("evaluate_step_advance scaffold - pending T-03026")
    }

    pub fn evaluate_scan_operation(
        &self,
        _action: &str,
        _ports_count: usize,
        _depth: usize,
    ) -> Result<(), String> {
        unimplemented!("evaluate_scan_operation scaffold - pending T-03026")
    }

    pub fn load_from_file(_path: &str) -> Result<Self, String> {
        unimplemented!("load_from_file scaffold - pending T-03026")
    }

    pub fn save_to_file(&self, _path: &str) -> Result<(), String> {
        unimplemented!("save_to_file scaffold - pending T-03026")
    }
}
