//! Threat Model Security Policy Subsystem (THREATPOL1..THREATPOL7).
//!
//! Provides declarative governance over threat entry registration,
//! lifecycle transitions, mitigation enforcement, and catalog density limits.

use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};

use crate::threat_model_data_model::{ThreatCategory, ThreatEntry, ThreatSeverity, ThreatStatus};
use crate::threat_model_service::ThreatRiskAssessment;

pub const THREATPOL_ERR_VALIDATION: &str = "THREATPOL_ERR_VALIDATION";
pub const THREATPOL_ERR_DENIED: &str = "THREATPOL_ERR_DENIED";
pub const THREATPOL_ERR_CWE_REQUIRED: &str = "THREATPOL_ERR_CWE_REQUIRED";
pub const THREATPOL_ERR_CRITICAL_UNMITIGATED: &str = "THREATPOL_ERR_CRITICAL_UNMITIGATED";
pub const THREATPOL_ERR_CATEGORY_PROHIBITED: &str = "THREATPOL_ERR_CATEGORY_PROHIBITED";
pub const THREATPOL_ERR_CAPACITY_EXCEEDED: &str = "THREATPOL_ERR_CAPACITY_EXCEEDED";
pub const THREATPOL_ERR_IO: &str = "THREATPOL_ERR_IO";
pub const THREATPOL_ERR_PARSE: &str = "THREATPOL_ERR_PARSE";

pub const MAX_THREAT_SECURITY_POLICY_BYTES: u64 = 65_536; // 64 KiB

/// Enforcement mode for Threat Model security policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatPolicyMode {
    /// Enforcing: Invariant violations fail-closed returning Deny.
    Enforcing,
    /// Permissive: Violations emit warning telemetry but permit access.
    Permissive,
    /// Disabled: Policy evaluation is bypassed.
    Disabled,
}

impl Default for ThreatPolicyMode {
    fn default() -> Self {
        Self::Enforcing
    }
}

/// Evaluation verdict for threat model operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ThreatPolicyVerdict {
    /// Permitted under policy.
    Permit,
    /// Permitted with an auditable security warning.
    PermitWithWarning { warning: String },
    /// Denied fail-closed under security policy.
    Deny { reason: String, code: String },
}

/// Declarative security policy for Threat Model Maintenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatModelSecurityPolicy {
    pub version: String,
    pub mode: ThreatPolicyMode,
    pub require_cwe_mapping: bool,
    pub disallow_unmitigated_critical: bool,
    pub prohibited_categories: Vec<ThreatCategory>,
    pub max_catalog_threats: usize,
    pub max_critical_threats: usize,
    pub allow_canonical_override: bool,
}

impl Default for ThreatModelSecurityPolicy {
    fn default() -> Self {
        Self {
            version: "1.0.0".into(),
            mode: ThreatPolicyMode::Enforcing,
            require_cwe_mapping: true,
            disallow_unmitigated_critical: true,
            prohibited_categories: vec![],
            max_catalog_threats: 512,
            max_critical_threats: 16,
            allow_canonical_override: false,
        }
    }
}

impl ThreatModelSecurityPolicy {
    /// Validates structural invariants and boundaries of the policy itself.
    pub fn validate(&self) -> Result<(), String> {
        if self.version.trim().is_empty() || !self.version.starts_with("1.") {
            return Err(format!("{}: version must begin with '1.'", THREATPOL_ERR_VALIDATION));
        }
        if self.max_catalog_threats == 0 || self.max_catalog_threats > 4096 {
            return Err(format!("{}: max_catalog_threats out of bounds [1, 4096]", THREATPOL_ERR_VALIDATION));
        }
        if self.max_critical_threats > self.max_catalog_threats {
            return Err(format!("{}: max_critical_threats cannot exceed max_catalog_threats", THREATPOL_ERR_VALIDATION));
        }
        Ok(())
    }

    /// Evaluates threat registration against policy.
    pub fn evaluate_registration(&self, entry: &ThreatEntry) -> ThreatPolicyVerdict {
        if self.mode == ThreatPolicyMode::Disabled {
            return ThreatPolicyVerdict::Permit;
        }

        // 1. Prohibited category check
        if self.prohibited_categories.contains(&entry.category) {
            let reason = format!("Threat category '{:?}' is prohibited by security policy", entry.category);
            return match self.mode {
                ThreatPolicyMode::Enforcing => ThreatPolicyVerdict::Deny { reason, code: THREATPOL_ERR_CATEGORY_PROHIBITED.into() },
                ThreatPolicyMode::Permissive => ThreatPolicyVerdict::PermitWithWarning { warning: reason },
                ThreatPolicyMode::Disabled => ThreatPolicyVerdict::Permit,
            };
        }

        // 2. CWE mapping check
        if self.require_cwe_mapping && entry.cwe_ids.is_empty() {
            let reason = "Threat entry requires at least one CWE identifier mapping".to_string();
            return match self.mode {
                ThreatPolicyMode::Enforcing => ThreatPolicyVerdict::Deny { reason, code: THREATPOL_ERR_CWE_REQUIRED.into() },
                ThreatPolicyMode::Permissive => ThreatPolicyVerdict::PermitWithWarning { warning: reason },
                ThreatPolicyMode::Disabled => ThreatPolicyVerdict::Permit,
            };
        }

        ThreatPolicyVerdict::Permit
    }

    /// Evaluates threat lifecycle transition against policy.
    pub fn evaluate_transition(&self, entry: &ThreatEntry, next_status: ThreatStatus) -> ThreatPolicyVerdict {
        if self.mode == ThreatPolicyMode::Disabled {
            return ThreatPolicyVerdict::Permit;
        }

        // Critical unmitigated transition guard
        if self.disallow_unmitigated_critical
            && entry.severity == ThreatSeverity::Critical
            && (next_status == ThreatStatus::Accepted || next_status == ThreatStatus::Resolved)
            && entry.mitigations.is_empty()
        {
            let reason = "Critical severity threats cannot be accepted or resolved without at least one mitigation recorded".to_string();
            return match self.mode {
                ThreatPolicyMode::Enforcing => ThreatPolicyVerdict::Deny { reason, code: THREATPOL_ERR_CRITICAL_UNMITIGATED.into() },
                ThreatPolicyMode::Permissive => ThreatPolicyVerdict::PermitWithWarning { warning: reason },
                ThreatPolicyMode::Disabled => ThreatPolicyVerdict::Permit,
            };
        }

        ThreatPolicyVerdict::Permit
    }

    /// Evaluates mitigation attachment against policy.
    pub fn evaluate_mitigation(&self, _entry: &ThreatEntry, mitigation: &str) -> ThreatPolicyVerdict {
        if self.mode == ThreatPolicyMode::Disabled {
            return ThreatPolicyVerdict::Permit;
        }

        if mitigation.trim().is_empty() {
            let reason = "Mitigation text cannot be empty".to_string();
            return match self.mode {
                ThreatPolicyMode::Enforcing => ThreatPolicyVerdict::Deny { reason, code: THREATPOL_ERR_DENIED.into() },
                ThreatPolicyMode::Permissive => ThreatPolicyVerdict::PermitWithWarning { warning: reason },
                ThreatPolicyMode::Disabled => ThreatPolicyVerdict::Permit,
            };
        }

        ThreatPolicyVerdict::Permit
    }

    /// Evaluates system risk assessment against catalog density policies.
    pub fn evaluate_assessment(&self, assessment: &ThreatRiskAssessment) -> ThreatPolicyVerdict {
        if self.mode == ThreatPolicyMode::Disabled {
            return ThreatPolicyVerdict::Permit;
        }

        if assessment.total_threats > self.max_catalog_threats {
            let reason = format!("Total threats ({}) exceeds maximum policy capacity ({})", assessment.total_threats, self.max_catalog_threats);
            return match self.mode {
                ThreatPolicyMode::Enforcing => ThreatPolicyVerdict::Deny { reason, code: THREATPOL_ERR_CAPACITY_EXCEEDED.into() },
                ThreatPolicyMode::Permissive => ThreatPolicyVerdict::PermitWithWarning { warning: reason },
                ThreatPolicyMode::Disabled => ThreatPolicyVerdict::Permit,
            };
        }

        if assessment.critical_unmitigated_count > self.max_critical_threats {
            let reason = format!("Unmitigated critical threats ({}) exceeds policy limit ({})", assessment.critical_unmitigated_count, self.max_critical_threats);
            return match self.mode {
                ThreatPolicyMode::Enforcing => ThreatPolicyVerdict::Deny { reason, code: THREATPOL_ERR_CAPACITY_EXCEEDED.into() },
                ThreatPolicyMode::Permissive => ThreatPolicyVerdict::PermitWithWarning { warning: reason },
                ThreatPolicyMode::Disabled => ThreatPolicyVerdict::Permit,
            };
        }

        ThreatPolicyVerdict::Permit
    }

    /// Loads security policy from a JSON file path.
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let p = path.as_ref();
        let meta = fs::symlink_metadata(p)
            .map_err(|e| format!("{}: cannot stat {:?}: {}", THREATPOL_ERR_IO, p, e))?;
        if meta.file_type().is_symlink() {
            return Err(format!("{}: symlinks rejected for policy files", THREATPOL_ERR_VALIDATION));
        }
        if meta.len() > MAX_THREAT_SECURITY_POLICY_BYTES {
            return Err(format!("{}: policy file size {} exceeds max {}", THREATPOL_ERR_VALIDATION, meta.len(), MAX_THREAT_SECURITY_POLICY_BYTES));
        }
        let data = fs::read_to_string(p)
            .map_err(|e| format!("{}: cannot read {:?}: {}", THREATPOL_ERR_IO, p, e))?;
        let policy: Self = serde_json::from_str(&data)
            .map_err(|e| format!("{}: invalid JSON in {:?}: {}", THREATPOL_ERR_PARSE, p, e))?;
        policy.validate()?;
        Ok(policy)
    }

    /// Atomically saves security policy to a JSON file.
    pub fn save_to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        self.validate()?;
        let p = path.as_ref();
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("{}: cannot create directory {:?}: {}", THREATPOL_ERR_IO, parent, e))?;
            }
        }
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| format!("{}: serialization failed: {}", THREATPOL_ERR_PARSE, e))?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let temp_path = p.with_extension(format!("tmp.{}.{}", std::process::id(), nanos));
        if let Err(e) = fs::write(&temp_path, &data) {
            let _ = fs::remove_file(&temp_path);
            return Err(format!("{}: failed writing tempfile: {}", THREATPOL_ERR_IO, e));
        }
        fs::rename(&temp_path, p).map_err(|e| {
            let _ = fs::remove_file(&temp_path);
            format!("{}: failed renaming to {:?}: {}", THREATPOL_ERR_IO, p, e)
        })?;
        Ok(())
    }
}
