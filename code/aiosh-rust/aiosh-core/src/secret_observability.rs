//! Secrets Handling Observability Subsystem (SECOBS1..SECOBS6).
//!
//! Provides point-in-time metrics aggregation, scope/kind distributions,
//! expiration tracking, and operational health status.

use std::collections::HashMap;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::audit::AuditRing;
use crate::secret_service::SecretService;

pub const SECOBS_ERR_VALIDATION: &str = "SECOBS_ERR_VALIDATION";
pub const SECOBS_ERR_SERVICE_INACCESSIBLE: &str = "SECOBS_ERR_SERVICE_INACCESSIBLE";

pub const MAX_TELEMETRY_TEXT_LEN: usize = 256;
pub const MAX_OUTCOME_DISTRIBUTION_ENTRIES: usize = 128;
pub const MAX_AUDIT_LOG_TAIL_ITEMS: i64 = 1000;

pub fn sanitize_telemetry_text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_TELEMETRY_TEXT_LEN)
        .collect::<String>()
        .trim()
        .to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecretObservabilityReport {
    pub generated_at_utc: String,
    pub total_secrets: usize,
    pub secrets_by_scope: HashMap<String, usize>,
    pub secrets_by_kind: HashMap<String, usize>,
    pub active_secrets_count: usize,
    pub expired_secrets_count: usize,
    pub policy_mode: String,
    pub is_healthy: bool,
    pub recent_audit_events_count: usize,
}

impl SecretObservabilityReport {
    /// Generates a point-in-time observability report by inspecting the SecretService and optional AuditRing.
    pub fn generate(service: &SecretService, ring: Option<&AuditRing>) -> Result<Self, String> {
        let all_meta = service.list_metadata(None, None);
        let total = all_meta.len();

        let mut secrets_by_scope = HashMap::new();
        let mut secrets_by_kind = HashMap::new();
        let mut active_count = 0;
        let mut expired_count = 0;

        for m in &all_meta {
            let scope_str = sanitize_telemetry_text(&m.scope.as_str());
            if secrets_by_scope.len() < MAX_OUTCOME_DISTRIBUTION_ENTRIES {
                *secrets_by_scope.entry(scope_str).or_insert(0) += 1;
            }

            let kind_str = sanitize_telemetry_text(m.kind.as_str());
            if secrets_by_kind.len() < MAX_OUTCOME_DISTRIBUTION_ENTRIES {
                *secrets_by_kind.entry(kind_str).or_insert(0) += 1;
            }

            if m.is_expired() {
                expired_count += 1;
            } else if m.state.is_accessible() {
                active_count += 1;
            }
        }

        let mut audit_events_count = 0;
        if let Some(r) = ring {
            if let Ok(rows) = r.tail(MAX_AUDIT_LOG_TAIL_ITEMS) {
                for row in rows {
                    if row.tool == "secret" || row.tool.starts_with("aios.secret") {
                        audit_events_count += 1;
                    }
                }
            }
        }

        let policy = service.policy();
        let policy_mode = format!("{:?}", policy.mode).to_lowercase();
        let is_healthy = total <= service.config().max_secrets_capacity;

        let report = Self {
            generated_at_utc: Utc::now().to_rfc3339(),
            total_secrets: total,
            secrets_by_scope,
            secrets_by_kind,
            active_secrets_count: active_count,
            expired_secrets_count: expired_count,
            policy_mode,
            is_healthy,
            recent_audit_events_count: audit_events_count,
        };

        report.validate()?;
        Ok(report)
    }

    /// Validates report telemetry invariants.
    pub fn validate(&self) -> Result<(), String> {
        if self.generated_at_utc.trim().is_empty() {
            return Err(format!("{}: generated_at_utc timestamp cannot be empty", SECOBS_ERR_VALIDATION));
        }

        if self.secrets_by_scope.len() > MAX_OUTCOME_DISTRIBUTION_ENTRIES {
            return Err(format!("{}: secrets_by_scope exceeds capacity limit", SECOBS_ERR_VALIDATION));
        }

        if self.secrets_by_kind.len() > MAX_OUTCOME_DISTRIBUTION_ENTRIES {
            return Err(format!("{}: secrets_by_kind exceeds capacity limit", SECOBS_ERR_VALIDATION));
        }

        Ok(())
    }
}
