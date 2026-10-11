//! Compliance Mapping Security Policy Subsystem (COMPLIANCEPOL1..COMPLIANCEPOL7).
//!
//! Provides declarative governance over compliance mapping registration,
//! lifecycle status transitions, framework enforcement, and assessment thresholds.

use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};

use crate::compliance_data_model::{ComplianceFramework, ComplianceMappingEntry, ComplianceStatus};
use crate::compliance_service::ComplianceAssessmentReport;

pub const COMPLIANCEPOL_ERR_VALIDATION: &str = "COMPLIANCEPOL_ERR_VALIDATION";
pub const COMPLIANCEPOL_ERR_DENIED: &str = "COMPLIANCEPOL_ERR_DENIED";
pub const COMPLIANCEPOL_ERR_THREAT_REQUIRED: &str = "COMPLIANCEPOL_ERR_THREAT_REQUIRED";
pub const COMPLIANCEPOL_ERR_MITIGATION_REQUIRED: &str = "COMPLIANCEPOL_ERR_MITIGATION_REQUIRED";
pub const COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED: &str = "COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED";
pub const COMPLIANCEPOL_ERR_THRESHOLD_UNMET: &str = "COMPLIANCEPOL_ERR_THRESHOLD_UNMET";
pub const COMPLIANCEPOL_ERR_CAPACITY_EXCEEDED: &str = "COMPLIANCEPOL_ERR_CAPACITY_EXCEEDED";
pub const COMPLIANCEPOL_ERR_OVERRIDE_FORBIDDEN: &str = "COMPLIANCEPOL_ERR_OVERRIDE_FORBIDDEN";
pub const COMPLIANCEPOL_ERR_IO: &str = "COMPLIANCEPOL_ERR_IO";
pub const COMPLIANCEPOL_ERR_PARSE: &str = "COMPLIANCEPOL_ERR_PARSE";

pub const MAX_COMPLIANCE_SECURITY_POLICY_BYTES: u64 = 65_536; // 64 KiB

/// Enforcement mode for Compliance Mapping security policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompliancePolicyMode {
    /// Enforcing: Invariant violations fail-closed returning Deny.
    Enforcing,
    /// Permissive: Violations emit warning telemetry but permit access.
    Permissive,
    /// Disabled: Policy evaluation is bypassed.
    Disabled,
}

impl Default for CompliancePolicyMode {
    fn default() -> Self {
        Self::Enforcing
    }
}

/// Evaluation verdict for compliance mapping operations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum CompliancePolicyVerdict {
    /// Permitted under policy.
    Permit,
    /// Permitted with an auditable security warning.
    PermitWithWarning { warning: String },
    /// Denied fail-closed under security policy.
    Deny { reason: String, code: String },
}

/// Declarative security policy for Compliance Mapping.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceSecurityPolicy {
    pub version: String,
    pub mode: CompliancePolicyMode,
    pub require_threat_linkage: bool,
    pub require_mitigation_on_compliant: bool,
    pub permitted_frameworks: Vec<ComplianceFramework>,
    pub min_compliant_percentage: f64,
    pub max_catalog_mappings: usize,
    pub allow_canonical_override: bool,
}

impl Default for ComplianceSecurityPolicy {
    fn default() -> Self {
        Self {
            version: "1.0.0".into(),
            mode: CompliancePolicyMode::Enforcing,
            require_threat_linkage: true,
            require_mitigation_on_compliant: true,
            permitted_frameworks: vec![],
            min_compliant_percentage: 80.0,
            max_catalog_mappings: 1024,
            allow_canonical_override: false,
        }
    }
}

impl ComplianceSecurityPolicy {
    /// Validates structural invariants and boundaries of the policy itself.
    pub fn validate(&self) -> Result<(), String> {
        if self.version.trim().is_empty() || !self.version.starts_with("1.") {
            return Err(format!("{}: version must begin with '1.'", COMPLIANCEPOL_ERR_VALIDATION));
        }
        if self.max_catalog_mappings == 0 || self.max_catalog_mappings > 4096 {
            return Err(format!("{}: max_catalog_mappings out of bounds [1, 4096]", COMPLIANCEPOL_ERR_VALIDATION));
        }
        if self.min_compliant_percentage < 0.0 || self.min_compliant_percentage > 100.0 {
            return Err(format!("{}: min_compliant_percentage out of bounds [0.0, 100.0]", COMPLIANCEPOL_ERR_VALIDATION));
        }
        Ok(())
    }

    /// Evaluates control mapping registration against policy.
    pub fn evaluate_registration(&self, entry: &ComplianceMappingEntry) -> CompliancePolicyVerdict {
        if self.mode == CompliancePolicyMode::Disabled {
            return CompliancePolicyVerdict::Permit;
        }

        // Framework whitelist
        if !self.permitted_frameworks.is_empty() && !self.permitted_frameworks.contains(&entry.framework) {
            let reason = format!("Framework '{:?}' is not permitted by security policy", entry.framework);
            return match self.mode {
                CompliancePolicyMode::Enforcing => CompliancePolicyVerdict::Deny {
                    reason,
                    code: COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED.into(),
                },
                CompliancePolicyMode::Permissive => CompliancePolicyVerdict::PermitWithWarning { warning: reason },
                CompliancePolicyMode::Disabled => CompliancePolicyVerdict::Permit,
            };
        }

        // Threat linkage
        if self.require_threat_linkage && entry.threat_ids.is_empty() {
            let reason = format!("Compliance entry '{}' requires at least one linked threat ID", entry.id);
            return match self.mode {
                CompliancePolicyMode::Enforcing => CompliancePolicyVerdict::Deny {
                    reason,
                    code: COMPLIANCEPOL_ERR_THREAT_REQUIRED.into(),
                },
                CompliancePolicyMode::Permissive => CompliancePolicyVerdict::PermitWithWarning { warning: reason },
                CompliancePolicyMode::Disabled => CompliancePolicyVerdict::Permit,
            };
        }

        // Status compliant requirement
        if self.require_mitigation_on_compliant && entry.status == ComplianceStatus::Compliant {
            let has_reason = entry.mitigation_summary.trim().len() >= 3;
            if !has_reason {
                let reason = format!("Entry '{}' cannot be marked Compliant without mitigation rationale", entry.id);
                return match self.mode {
                    CompliancePolicyMode::Enforcing => CompliancePolicyVerdict::Deny {
                        reason,
                        code: COMPLIANCEPOL_ERR_MITIGATION_REQUIRED.into(),
                    },
                    CompliancePolicyMode::Permissive => CompliancePolicyVerdict::PermitWithWarning { warning: reason },
                    CompliancePolicyMode::Disabled => CompliancePolicyVerdict::Permit,
                };
            }
        }

        CompliancePolicyVerdict::Permit
    }

    /// Evaluates status transition against policy.
    pub fn evaluate_status_transition(
        &self,
        entry: &ComplianceMappingEntry,
        new_status: ComplianceStatus,
        reason_or_mitigation: &str,
    ) -> CompliancePolicyVerdict {
        if self.mode == CompliancePolicyMode::Disabled {
            return CompliancePolicyVerdict::Permit;
        }

        if self.require_mitigation_on_compliant && new_status == ComplianceStatus::Compliant {
            if reason_or_mitigation.trim().len() < 3 {
                let reason = format!(
                    "Transitioning '{}' to Compliant requires documented mitigation summary (minimum 3 chars)",
                    entry.id
                );
                return match self.mode {
                    CompliancePolicyMode::Enforcing => CompliancePolicyVerdict::Deny {
                        reason,
                        code: COMPLIANCEPOL_ERR_MITIGATION_REQUIRED.into(),
                    },
                    CompliancePolicyMode::Permissive => CompliancePolicyVerdict::PermitWithWarning { warning: reason },
                    CompliancePolicyMode::Disabled => CompliancePolicyVerdict::Permit,
                };
            }
        }

        CompliancePolicyVerdict::Permit
    }

    /// Evaluates compliance assessment report against threshold.
    pub fn evaluate_assessment(&self, report: &ComplianceAssessmentReport) -> CompliancePolicyVerdict {
        if self.mode == CompliancePolicyMode::Disabled {
            return CompliancePolicyVerdict::Permit;
        }

        if report.compliance_percentage < self.min_compliant_percentage {
            let reason = format!(
                "Assessment compliance percentage {:.1}% falls below policy threshold {:.1}%",
                report.compliance_percentage, self.min_compliant_percentage
            );
            return match self.mode {
                CompliancePolicyMode::Enforcing => CompliancePolicyVerdict::Deny {
                    reason,
                    code: COMPLIANCEPOL_ERR_THRESHOLD_UNMET.into(),
                },
                CompliancePolicyMode::Permissive => CompliancePolicyVerdict::PermitWithWarning { warning: reason },
                CompliancePolicyMode::Disabled => CompliancePolicyVerdict::Permit,
            };
        }

        CompliancePolicyVerdict::Permit
    }

    /// Evaluates override capability against policy.
    pub fn evaluate_override(&self, _caller: &str) -> CompliancePolicyVerdict {
        if self.mode == CompliancePolicyMode::Disabled {
            return CompliancePolicyVerdict::Permit;
        }

        if !self.allow_canonical_override {
            let reason = "Canonical compliance override forbidden by security policy".into();
            return match self.mode {
                CompliancePolicyMode::Enforcing => CompliancePolicyVerdict::Deny {
                    reason,
                    code: COMPLIANCEPOL_ERR_OVERRIDE_FORBIDDEN.into(),
                },
                CompliancePolicyMode::Permissive => CompliancePolicyVerdict::PermitWithWarning { warning: reason },
                CompliancePolicyMode::Disabled => CompliancePolicyVerdict::Permit,
            };
        }

        CompliancePolicyVerdict::Permit
    }

    /// Loads policy from JSON file with file size and symlink protections.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let meta = fs::symlink_metadata(path)
            .map_err(|e| format!("{}: cannot stat policy path: {}", COMPLIANCEPOL_ERR_IO, e))?;

        if meta.file_type().is_symlink() {
            return Err(format!("{}: symlinks rejected for security policy", COMPLIANCEPOL_ERR_IO));
        }

        if meta.len() > MAX_COMPLIANCE_SECURITY_POLICY_BYTES {
            return Err(format!(
                "{}: policy file size {} exceeds maximum {}",
                COMPLIANCEPOL_ERR_IO, meta.len(), MAX_COMPLIANCE_SECURITY_POLICY_BYTES
            ));
        }

        let content = fs::read_to_string(path)
            .map_err(|e| format!("{}: read failed: {}", COMPLIANCEPOL_ERR_IO, e))?;

        let policy: Self = serde_json::from_str(&content)
            .map_err(|e| format!("{}: parse error: {}", COMPLIANCEPOL_ERR_PARSE, e))?;

        policy.validate()?;
        Ok(policy)
    }

    /// Saves policy atomically to file.
    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        self.validate()?;
        let serialized = serde_json::to_string_pretty(self)
            .map_err(|e| format!("{}: serialize failed: {}", COMPLIANCEPOL_ERR_PARSE, e))?;

        if serialized.len() as u64 > MAX_COMPLIANCE_SECURITY_POLICY_BYTES {
            return Err(format!(
                "{}: serialized policy exceeds cap",
                COMPLIANCEPOL_ERR_IO
            ));
        }

        let tmp = path.with_extension("tmp");
        fs::write(&tmp, serialized)
            .map_err(|e| format!("{}: write failed: {}", COMPLIANCEPOL_ERR_IO, e))?;

        fs::rename(&tmp, path)
            .map_err(|e| format!("{}: atomic rename failed: {}", COMPLIANCEPOL_ERR_IO, e))?;

        Ok(())
    }
}
