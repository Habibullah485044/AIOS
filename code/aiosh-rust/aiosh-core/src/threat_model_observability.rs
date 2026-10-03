//! Threat Model Observability Subsystem (THREATOBS1..THREATOBS6).
//!
//! Provides point-in-time metrics aggregation, STRIDE category distributions,
//! severity distributions, lifecycle status progression tracking, and
//! risk exposure scoring for Threat Model Maintenance.

use std::collections::HashMap;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::audit::AuditRing;
use crate::threat_model_service::ThreatModelService;

pub const THREATOBS_ERR_VALIDATION: &str = "THREATOBS_ERR_VALIDATION";
pub const THREATOBS_ERR_SERVICE_INACCESSIBLE: &str = "THREATOBS_ERR_SERVICE_INACCESSIBLE";

pub const MAX_TELEMETRY_TEXT_LEN: usize = 256;
pub const MAX_OUTCOME_DISTRIBUTION_ENTRIES: usize = 128;
pub const MAX_AUDIT_LOG_TAIL_ITEMS: i64 = 1000;

/// Sanitizes telemetry text by filtering control characters and enforcing length bounds.
pub fn sanitize_telemetry_text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_TELEMETRY_TEXT_LEN)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Point-in-time observability report for Threat Model Maintenance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatModelObservabilityReport {
    pub generated_at_utc: String,
    pub total_threats: usize,
    pub threats_by_category: HashMap<String, usize>,
    pub threats_by_severity: HashMap<String, usize>,
    pub threats_by_status: HashMap<String, usize>,
    pub critical_unmitigated_count: usize,
    pub overall_risk_score: u32,
    pub policy_mode: String,
    pub is_healthy: bool,
    pub recent_audit_events_count: usize,
}

impl ThreatModelObservabilityReport {
    /// Generates a point-in-time observability report by inspecting ThreatModelService and optional AuditRing.
    pub fn generate(service: &ThreatModelService, ring: Option<&AuditRing>) -> Result<Self, String> {
        let threats = service.list_threats();
        let total = threats.len();

        let mut threats_by_category = HashMap::new();
        let mut threats_by_severity = HashMap::new();
        let mut threats_by_status = HashMap::new();

        for entry in threats {
            let cat_str = sanitize_telemetry_text(entry.category.as_str());
            if threats_by_category.len() < MAX_OUTCOME_DISTRIBUTION_ENTRIES {
                *threats_by_category.entry(cat_str).or_insert(0) += 1;
            }

            let sev_str = sanitize_telemetry_text(entry.severity.as_str());
            if threats_by_severity.len() < MAX_OUTCOME_DISTRIBUTION_ENTRIES {
                *threats_by_severity.entry(sev_str).or_insert(0) += 1;
            }

            let stat_str = sanitize_telemetry_text(entry.status.as_str());
            if threats_by_status.len() < MAX_OUTCOME_DISTRIBUTION_ENTRIES {
                *threats_by_status.entry(stat_str).or_insert(0) += 1;
            }
        }

        let assessment = service.assess_risk();

        let mut audit_events_count = 0;
        if let Some(r) = ring {
            if let Ok(rows) = r.tail(MAX_AUDIT_LOG_TAIL_ITEMS) {
                for row in rows {
                    if row.tool == "threat" || row.tool.starts_with("aios.threat") {
                        audit_events_count += 1;
                    }
                }
            }
        }

        let policy_mode = if let Some(ref pol) = service.policy() {
            format!("{:?}", pol.mode).to_lowercase()
        } else {
            "unconfigured".to_string()
        };

        let is_healthy = total <= crate::threat_model_service::MAX_THREAT_ENTRIES_CAPACITY;

        let report = Self {
            generated_at_utc: Utc::now().to_rfc3339(),
            total_threats: total,
            threats_by_category,
            threats_by_severity,
            threats_by_status,
            critical_unmitigated_count: assessment.critical_unmitigated_count,
            overall_risk_score: assessment.overall_risk_score,
            policy_mode,
            is_healthy,
            recent_audit_events_count: audit_events_count,
        };

        report.validate()?;
        Ok(report)
    }

    /// Validates report invariants and sanity bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.generated_at_utc.trim().is_empty() {
            return Err(format!("{}: generated_at_utc cannot be empty", THREATOBS_ERR_VALIDATION));
        }

        if chrono::DateTime::parse_from_rfc3339(&self.generated_at_utc).is_err() {
            return Err(format!("{}: invalid RFC3339 timestamp in generated_at_utc", THREATOBS_ERR_VALIDATION));
        }

        if self.threats_by_category.len() > MAX_OUTCOME_DISTRIBUTION_ENTRIES {
            return Err(format!("{}: threats_by_category exceeds max entries", THREATOBS_ERR_VALIDATION));
        }

        if self.threats_by_severity.len() > MAX_OUTCOME_DISTRIBUTION_ENTRIES {
            return Err(format!("{}: threats_by_severity exceeds max entries", THREATOBS_ERR_VALIDATION));
        }

        if self.threats_by_status.len() > MAX_OUTCOME_DISTRIBUTION_ENTRIES {
            return Err(format!("{}: threats_by_status exceeds max entries", THREATOBS_ERR_VALIDATION));
        }

        for (k, _) in &self.threats_by_category {
            if k.len() > MAX_TELEMETRY_TEXT_LEN {
                return Err(format!("{}: category label exceeds max length", THREATOBS_ERR_VALIDATION));
            }
        }

        for (k, _) in &self.threats_by_severity {
            if k.len() > MAX_TELEMETRY_TEXT_LEN {
                return Err(format!("{}: severity label exceeds max length", THREATOBS_ERR_VALIDATION));
            }
        }

        for (k, _) in &self.threats_by_status {
            if k.len() > MAX_TELEMETRY_TEXT_LEN {
                return Err(format!("{}: status label exceeds max length", THREATOBS_ERR_VALIDATION));
            }
        }

        Ok(())
    }

    /// Serializes report to pretty-printed JSON.
    pub fn to_json(&self) -> Result<String, String> {
        self.validate()?;
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("{}: JSON serialization error: {}", THREATOBS_ERR_VALIDATION, e))
    }

    /// Deserializes and validates report from JSON.
    pub fn from_json(json_str: &str) -> Result<Self, String> {
        let report: Self = serde_json::from_str(json_str)
            .map_err(|e| format!("{}: JSON parsing error: {}", THREATOBS_ERR_VALIDATION, e))?;
        report.validate()?;
        Ok(report)
    }
}

