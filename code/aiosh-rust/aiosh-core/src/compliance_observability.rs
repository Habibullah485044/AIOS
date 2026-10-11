//! Compliance Mapping Observability Subsystem (COMPOBS1..COMPOBS6).
//!
//! Provides point-in-time metrics aggregation, regulatory framework distributions,
//! lifecycle status distributions, target component distributions, posture scoring,
//! capacity utilization telemetry, and audit trail correlation.

use std::collections::HashMap;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::audit::AuditRing;
use crate::compliance_service::ComplianceService;
use crate::compliance_data_model::MAX_COMPLIANCE_ENTRIES_CAPACITY;

pub const COMPOBS_ERR_VALIDATION: &str = "COMPOBS_ERR_VALIDATION";
pub const COMPOBS_ERR_SERVICE_INACCESSIBLE: &str = "COMPOBS_ERR_SERVICE_INACCESSIBLE";

pub const MAX_TELEMETRY_TEXT_LEN: usize = 256;
pub const MAX_OUTCOME_DISTRIBUTION_ENTRIES: usize = 128;
pub const MAX_AUDIT_LOG_TAIL_ITEMS: i64 = 1000;

/// Sanitizes telemetry text by removing control characters, zero-width chars, trimming, and bounding length.
pub fn sanitize_telemetry_text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && *c != '\u{200b}' && *c != '\u{200c}' && *c != '\u{200d}' && *c != '\u{feff}')
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
    pub fn generate(service: &ComplianceService, ring: Option<&AuditRing>) -> Result<Self, String> {
        Self::generate_with_timestamp(service, ring, None)
    }

    /// Generates a report with an optional custom timestamp (RFC3339).
    pub fn generate_with_timestamp(
        service: &ComplianceService,
        ring: Option<&AuditRing>,
        timestamp: Option<&str>,
    ) -> Result<Self, String> {
        let generated_at_utc = match timestamp {
            Some(ts) => {
                let sanitized = sanitize_telemetry_text(ts);
                if chrono::DateTime::parse_from_rfc3339(&sanitized).is_err() {
                    return Err(format!("{}: provided timestamp is not valid RFC3339: {}", COMPOBS_ERR_VALIDATION, sanitized));
                }
                sanitized
            }
            None => Utc::now().to_rfc3339(),
        };

        let mappings = &service.snapshot.mappings;
        let total = mappings.len();

        let mut mappings_by_framework = HashMap::new();
        let mut mappings_by_status = HashMap::new();
        let mut mappings_by_target_type = HashMap::new();

        for entry in mappings {
            let fw_str = sanitize_telemetry_text(entry.framework.as_str());
            if mappings_by_framework.len() < MAX_OUTCOME_DISTRIBUTION_ENTRIES || mappings_by_framework.contains_key(&fw_str) {
                *mappings_by_framework.entry(fw_str).or_insert(0) += 1;
            }

            let stat_str = sanitize_telemetry_text(entry.status.as_str());
            if mappings_by_status.len() < MAX_OUTCOME_DISTRIBUTION_ENTRIES || mappings_by_status.contains_key(&stat_str) {
                *mappings_by_status.entry(stat_str).or_insert(0) += 1;
            }

            let tt_str = sanitize_telemetry_text(entry.target_type.as_str());
            if mappings_by_target_type.len() < MAX_OUTCOME_DISTRIBUTION_ENTRIES || mappings_by_target_type.contains_key(&tt_str) {
                *mappings_by_target_type.entry(tt_str).or_insert(0) += 1;
            }
        }

        let assessment = service.assess_framework(None);

        let mut recent_audit_events_count = 0;
        if let Some(r) = ring {
            if let Ok(rows) = r.tail(MAX_AUDIT_LOG_TAIL_ITEMS) {
                for row in rows {
                    if row.tool == "compliance" || row.tool.starts_with("aios.compliance") {
                        recent_audit_events_count += 1;
                    }
                }
            }
        }

        let policy_mode = if let Some(ref pol) = service.policy {
            format!("{:?}", pol.mode).to_lowercase()
        } else {
            "unconfigured".to_string()
        };

        let capacity_utilization_percent = if MAX_COMPLIANCE_ENTRIES_CAPACITY == 0 {
            0
        } else {
            ((total.min(MAX_COMPLIANCE_ENTRIES_CAPACITY) * 100) / MAX_COMPLIANCE_ENTRIES_CAPACITY) as u8
        };

        let is_healthy = total <= MAX_COMPLIANCE_ENTRIES_CAPACITY
            && assessment.compliance_percentage.is_finite()
            && !assessment.compliance_percentage.is_nan();

        let report = Self {
            generated_at_utc,
            total_mappings: total,
            mappings_by_framework,
            mappings_by_status,
            mappings_by_target_type,
            compliance_percentage: assessment.compliance_percentage,
            gap_control_count: assessment.gap_control_ids.len(),
            policy_mode,
            capacity_utilization_percent,
            is_healthy,
            recent_audit_events_count,
        };

        report.validate()?;
        Ok(report)
    }

    /// Validates internal consistency and invariant bounds of the report.
    pub fn validate(&self) -> Result<(), String> {
        if self.generated_at_utc.trim().is_empty() {
            return Err(format!("{}: generated_at_utc cannot be empty", COMPOBS_ERR_VALIDATION));
        }

        if chrono::DateTime::parse_from_rfc3339(&self.generated_at_utc).is_err() {
            return Err(format!("{}: generated_at_utc must be valid RFC3339 timestamp", COMPOBS_ERR_VALIDATION));
        }

        if self.mappings_by_framework.len() > MAX_OUTCOME_DISTRIBUTION_ENTRIES {
            return Err(format!("{}: mappings_by_framework exceeds maximum entries", COMPOBS_ERR_VALIDATION));
        }
        if self.mappings_by_status.len() > MAX_OUTCOME_DISTRIBUTION_ENTRIES {
            return Err(format!("{}: mappings_by_status exceeds maximum entries", COMPOBS_ERR_VALIDATION));
        }
        if self.mappings_by_target_type.len() > MAX_OUTCOME_DISTRIBUTION_ENTRIES {
            return Err(format!("{}: mappings_by_target_type exceeds maximum entries", COMPOBS_ERR_VALIDATION));
        }

        if !self.compliance_percentage.is_finite()
            || self.compliance_percentage < 0.0
            || self.compliance_percentage > 100.0
            || self.compliance_percentage.is_nan()
        {
            return Err(format!("{}: compliance_percentage must be a finite float between 0.0 and 100.0", COMPOBS_ERR_VALIDATION));
        }

        if self.capacity_utilization_percent > 100 {
            return Err(format!("{}: capacity_utilization_percent cannot exceed 100", COMPOBS_ERR_VALIDATION));
        }

        if self.recent_audit_events_count > (MAX_AUDIT_LOG_TAIL_ITEMS as usize) {
            return Err(format!("{}: recent_audit_events_count exceeds max audit log tail items", COMPOBS_ERR_VALIDATION));
        }

        for k in self.mappings_by_framework.keys().chain(self.mappings_by_status.keys()).chain(self.mappings_by_target_type.keys()) {
            if k.len() > MAX_TELEMETRY_TEXT_LEN {
                return Err(format!("{}: distribution key exceeds max length", COMPOBS_ERR_VALIDATION));
            }
            if k.chars().any(|c| c.is_control() || c == '\u{200b}' || c == '\u{feff}') {
                return Err(format!("{}: distribution key contains forbidden/control characters", COMPOBS_ERR_VALIDATION));
            }
        }

        Ok(())
    }
}
