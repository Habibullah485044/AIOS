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

impl CompliancePolicyVerdict {
    pub fn is_permitted(&self) -> bool {
        matches!(self, Self::Permit | Self::PermitWithWarning { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
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
    pub fn permissive() -> Self {
        Self {
            mode: CompliancePolicyMode::Permissive,
            ..Self::default()
        }
    }

    pub fn disabled() -> Self {
        Self {
            mode: CompliancePolicyMode::Disabled,
            ..Self::default()
        }
    }

    /// Validates structural invariants and boundaries of the policy itself.
    pub fn validate(&self) -> Result<(), String> {
        if self.version.trim().is_empty() || !self.version.starts_with("1.") {
            return Err(format!("{}: version must begin with '1.'", COMPLIANCEPOL_ERR_VALIDATION));
        }
        if self.version.len() > 32 {
            return Err(format!("{}: version length exceeds maximum 32", COMPLIANCEPOL_ERR_VALIDATION));
        }
        if self.permitted_frameworks.len() > 16 {
            return Err(format!("{}: permitted_frameworks count exceeds maximum 16", COMPLIANCEPOL_ERR_VALIDATION));
        }
        if self.max_catalog_mappings == 0 || self.max_catalog_mappings > 4096 {
            return Err(format!("{}: max_catalog_mappings out of bounds [1, 4096]", COMPLIANCEPOL_ERR_VALIDATION));
        }
        if self.min_compliant_percentage < 0.0 || self.min_compliant_percentage > 100.0 || self.min_compliant_percentage.is_nan() {
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

    /// Evaluates capacity constraints.
    pub fn evaluate_capacity(&self, current_count: usize) -> CompliancePolicyVerdict {
        if self.mode == CompliancePolicyMode::Disabled {
            return CompliancePolicyVerdict::Permit;
        }

        if current_count >= self.max_catalog_mappings {
            let reason = format!(
                "Compliance catalog entry count {} reaches policy maximum {}",
                current_count, self.max_catalog_mappings
            );
            return match self.mode {
                CompliancePolicyMode::Enforcing => CompliancePolicyVerdict::Deny {
                    reason,
                    code: COMPLIANCEPOL_ERR_CAPACITY_EXCEEDED.into(),
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
    pub fn load_from_path<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let p = path.as_ref();
        let meta = fs::symlink_metadata(p)
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

        use std::io::Read;
        let f = fs::File::open(p)
            .map_err(|e| format!("{}: cannot open policy file: {}", COMPLIANCEPOL_ERR_IO, e))?;
        let mut buffer = Vec::new();
        f.take(MAX_COMPLIANCE_SECURITY_POLICY_BYTES + 1)
            .read_to_end(&mut buffer)
            .map_err(|e| format!("{}: read failed: {}", COMPLIANCEPOL_ERR_IO, e))?;

        if buffer.len() as u64 > MAX_COMPLIANCE_SECURITY_POLICY_BYTES {
            return Err(format!(
                "{}: policy file size exceeds maximum {}",
                COMPLIANCEPOL_ERR_IO, MAX_COMPLIANCE_SECURITY_POLICY_BYTES
            ));
        }

        let policy: Self = serde_json::from_slice(&buffer)
            .map_err(|e| format!("{}: parse error: {}", COMPLIANCEPOL_ERR_PARSE, e))?;

        policy.validate()?;
        Ok(policy)
    }

    /// Saves policy atomically to file.
    pub fn save_to_path<P: AsRef<Path>>(&self, path: P) -> Result<(), String> {
        self.validate()?;
        let p = path.as_ref();
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("{}: cannot create directory {:?}: {}", COMPLIANCEPOL_ERR_IO, parent, e))?;
            }
        }

        let serialized = serde_json::to_string_pretty(self)
            .map_err(|e| format!("{}: serialize failed: {}", COMPLIANCEPOL_ERR_PARSE, e))?;

        if serialized.len() as u64 > MAX_COMPLIANCE_SECURITY_POLICY_BYTES {
            return Err(format!(
                "{}: serialized policy exceeds cap",
                COMPLIANCEPOL_ERR_IO
            ));
        }

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let temp_path = p.with_extension(format!("tmp.{}.{}", std::process::id(), nanos));

        if let Err(e) = fs::write(&temp_path, &serialized) {
            let _ = fs::remove_file(&temp_path);
            return Err(format!("{}: write failed: {}", COMPLIANCEPOL_ERR_IO, e));
        }

        fs::rename(&temp_path, p).map_err(|e| {
            let _ = fs::remove_file(&temp_path);
            format!("{}: atomic rename failed: {}", COMPLIANCEPOL_ERR_IO, e)
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance_data_model::SubstrateTargetType;

    fn sample_entry(status: ComplianceStatus, mitigation: &str, threats: Vec<&str>) -> ComplianceMappingEntry {
        ComplianceMappingEntry {
            id: "map-test-01".into(),
            control_id: "AC-1".into(),
            framework: ComplianceFramework::NistSp80053Rev5,
            target_type: SubstrateTargetType::PepGate,
            target_ref: "pep:gate:test".into(),
            threat_ids: threats.into_iter().map(String::from).collect(),
            status,
            mitigation_summary: mitigation.into(),
            tags: vec!["test".into()],
            created_at: "2026-10-11T00:00:00Z".into(),
            updated_at: "2026-10-11T00:00:00Z".into(),
        }
    }

    #[test]
    fn test_policy_validation_invariants() {
        let mut policy = ComplianceSecurityPolicy::default();
        assert!(policy.validate().is_ok());

        policy.version = "2.0.0".into();
        assert!(policy.validate().is_err());

        policy.version = "1.0.0".into();
        policy.max_catalog_mappings = 0;
        assert!(policy.validate().is_err());

        policy.max_catalog_mappings = 5000;
        assert!(policy.validate().is_err());

        policy.max_catalog_mappings = 1024;
        policy.min_compliant_percentage = 105.0;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn test_registration_evaluation() {
        let policy = ComplianceSecurityPolicy::default();

        // Happy path
        let ok_entry = sample_entry(ComplianceStatus::Compliant, "Mitigated with PEP gate", vec!["THREAT-1"]);
        assert_eq!(policy.evaluate_registration(&ok_entry), CompliancePolicyVerdict::Permit);

        // Missing threat
        let no_threat = sample_entry(ComplianceStatus::NonCompliant, "", vec![]);
        assert!(matches!(
            policy.evaluate_registration(&no_threat),
            CompliancePolicyVerdict::Deny { ref code, .. } if code == COMPLIANCEPOL_ERR_THREAT_REQUIRED
        ));

        // Compliant without mitigation
        let no_mitigation = sample_entry(ComplianceStatus::Compliant, "", vec!["THREAT-1"]);
        assert!(matches!(
            policy.evaluate_registration(&no_mitigation),
            CompliancePolicyVerdict::Deny { ref code, .. } if code == COMPLIANCEPOL_ERR_MITIGATION_REQUIRED
        ));
    }

    #[test]
    fn test_framework_whitelist() {
        let mut policy = ComplianceSecurityPolicy::default();
        policy.permitted_frameworks = vec![ComplianceFramework::Soc2Type2];

        let nist_entry = sample_entry(ComplianceStatus::NonCompliant, "", vec!["THREAT-1"]);
        assert!(matches!(
            policy.evaluate_registration(&nist_entry),
            CompliancePolicyVerdict::Deny { ref code, .. } if code == COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED
        ));
    }

    #[test]
    fn test_permissive_mode() {
        let policy = ComplianceSecurityPolicy::permissive();
        let no_threat = sample_entry(ComplianceStatus::NonCompliant, "", vec![]);
        assert!(matches!(
            policy.evaluate_registration(&no_threat),
            CompliancePolicyVerdict::PermitWithWarning { .. }
        ));
    }

    #[test]
    fn test_disabled_mode() {
        let policy = ComplianceSecurityPolicy::disabled();
        let no_threat = sample_entry(ComplianceStatus::NonCompliant, "", vec![]);
        assert_eq!(policy.evaluate_registration(&no_threat), CompliancePolicyVerdict::Permit);
    }
}
