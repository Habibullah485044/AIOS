//! Compliance Mapping Observability Subsystem (COMPOBS1..COMPOBS6).
//!
//! Provides point-in-time metrics aggregation, regulatory framework distributions,
//! lifecycle status distributions, target component distributions, posture scoring,
//! capacity utilization telemetry, and audit trail correlation.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::audit::AuditRing;
use crate::compliance_service::ComplianceService;

pub const COMPOBS_ERR_VALIDATION: &str = "COMPOBS_ERR_VALIDATION";
pub const COMPOBS_ERR_SERVICE_INACCESSIBLE: &str = "COMPOBS_ERR_SERVICE_INACCESSIBLE";

pub const MAX_TELEMETRY_TEXT_LEN: usize = 256;
pub const MAX_OUTCOME_DISTRIBUTION_ENTRIES: usize = 128;
pub const MAX_AUDIT_LOG_TAIL_ITEMS: i64 = 1000;

/// Sanitizes telemetry text by removing control characters, trimming, and bounding length.
pub fn sanitize_telemetry_text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_TELEMETRY_TEXT_LEN)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Point-in-time observability report for Compliance Mapping.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComplianceObservabilityReport {
    pub generated_at_utc: String,
    pub total_mappings: usize,
    pub mappings_by_framework: HashMap<String, usize>,
    pub mappings_by_status: HashMap<String, usize>,
    pub mappings_by_target_type: HashMap<String, usize>,
    pub compliance_percentage: f64,
    pub gap_control_count: usize,
    pub policy_mode: String,
    pub capacity_utilization_percent: u8,
    pub is_healthy: bool,
    pub recent_audit_events_count: usize,
}

impl ComplianceObservabilityReport {
    /// Generates a point-in-time observability report from ComplianceService and optional AuditRing.
    pub fn generate(_service: &ComplianceService, _ring: Option<&AuditRing>) -> Result<Self, String> {
        // Scaffold stub (T-02935): fails loudly
        Err("not implemented: ComplianceObservabilityReport::generate (T-02935 scaffold)".to_string())
    }

    /// Validates internal consistency and invariant bounds of the report.
    pub fn validate(&self) -> Result<(), String> {
        // Scaffold stub (T-02935): fails loudly
        Err("not implemented: ComplianceObservabilityReport::validate (T-02935 scaffold)".to_string())
    }
}
