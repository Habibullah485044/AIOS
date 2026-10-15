//! Incident Response Runbooks Observability Subsystem (T-03033..T-03042).
//!
//! Provides point-in-time metrics aggregation, execution state summaries,
//! phase progression, scan budgets, and policy compliance posture.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::incident_runbook_data_model::{IncidentCategory, RunbookPhase};
use crate::incident_runbook_policy::RunbookEnforcementMode;

pub const MAX_OBSERVABILITY_PAYLOAD_BYTES: u64 = 64 * 1024;
pub const MAX_OBSERVABILITY_ENTRIES: usize = 128;
pub const MAX_OBSERVABILITY_TEXT_LEN: usize = 256;

pub const IROBS_ERR_VALIDATION: &str = "IROBS_ERR_VALIDATION";
pub const IROBS_ERR_INACCESSIBLE: &str = "IROBS_ERR_INACCESSIBLE";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunbookObservabilitySnapshot {
    pub generated_at_utc: String,
    pub total_catalog_runbooks: usize,
    pub total_executions: usize,
    pub executions_by_category: HashMap<IncidentCategory, usize>,
    pub executions_by_status: HashMap<String, usize>,
    pub step_executions_by_phase: HashMap<RunbookPhase, usize>,
    pub total_ports_scanned: usize,
    pub total_files_scanned: usize,
    pub total_web_paths_scanned: usize,
    pub policy_mode: RunbookEnforcementMode,
    pub high_risk_confirmations_total: usize,
    pub policy_rejections_total: usize,
    pub active_sessions_count: usize,
    pub active_sessions_utilization_percent: f64,
    pub is_healthy: bool,
    pub recent_audit_events_count: usize,
}

pub struct RunbookObservabilityService;

impl RunbookObservabilityService {
    pub fn generate_snapshot() -> Result<RunbookObservabilitySnapshot, String> {
        // Scaffold stub: fails loudly until implementation in T-03036
        panic!("pending T-03036: RunbookObservabilityService::generate_snapshot implementation");
    }

    pub fn validate_snapshot(_snapshot: &RunbookObservabilitySnapshot) -> Result<(), String> {
        // Scaffold stub: fails loudly until implementation in T-03036
        panic!("pending T-03036: RunbookObservabilityService::validate_snapshot implementation");
    }
}
