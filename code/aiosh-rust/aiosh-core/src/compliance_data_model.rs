//! Compliance Mapping Data Model (COMPLY1..COMPLY5).
//!
//! Provides the formal domain primitives, framework standards taxonomy,
//! substrate target bindings, and catalog snapshots for AIOS compliance mappings.

use std::fmt;
use serde::{Deserialize, Serialize};
use crate::canonical::utcnow_iso;

pub const MAX_COMPLIANCE_ID_LEN: usize = 64;
pub const MAX_COMPLIANCE_TITLE_LEN: usize = 128;
pub const MAX_COMPLIANCE_DESC_LEN: usize = 2048;
pub const MAX_COMPLIANCE_NOTES_LEN: usize = 2048;
pub const MAX_THREAT_IDS_COUNT: usize = 16;
pub const MAX_TAGS_COUNT: usize = 16;
pub const MAX_COMPLIANCE_ENTRIES_CAPACITY: usize = 1024;

pub const COMPLIANCE_ERR_INVALID_ID: &str = "COMPLIANCE_ERR_INVALID_ID";
pub const COMPLIANCE_ERR_INVALID_TITLE: &str = "COMPLIANCE_ERR_INVALID_TITLE";
pub const COMPLIANCE_ERR_BOUNDS_EXCEEDED: &str = "COMPLIANCE_ERR_BOUNDS_EXCEEDED";
pub const COMPLIANCE_ERR_CONTROL_CHARS: &str = "COMPLIANCE_ERR_CONTROL_CHARS";
pub const COMPLIANCE_ERR_DUPLICATE_ID: &str = "COMPLIANCE_ERR_DUPLICATE_ID";
pub const COMPLIANCE_ERR_INVALID_STATUS_TRANSITION: &str = "COMPLIANCE_ERR_INVALID_STATUS_TRANSITION";
pub const COMPLIANCE_ERR_MISSING_SUBSTRATE_REF: &str = "COMPLIANCE_ERR_MISSING_SUBSTRATE_REF";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    NistSp80053Rev5,
    Soc2Type2,
    Iso27001,
    CisControlsV8,
    HipaaSecurity,
    PciDssV4,
}

impl ComplianceFramework {
    pub fn as_str(&self) -> &'static str {
        match self {
            ComplianceFramework::NistSp80053Rev5 => "nist_sp_800_53_rev5",
            ComplianceFramework::Soc2Type2 => "soc2_type2",
            ComplianceFramework::Iso27001 => "iso_27001_2022",
            ComplianceFramework::CisControlsV8 => "cis_controls_v8",
            ComplianceFramework::HipaaSecurity => "hipaa_security",
            ComplianceFramework::PciDssV4 => "pci_dss_v4",
        }
    }

    pub fn parse_framework(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "nist_sp_800_53_rev5" | "nist" | "nist_800_53" => Some(ComplianceFramework::NistSp80053Rev5),
            "soc2_type2" | "soc2" | "soc_2" => Some(ComplianceFramework::Soc2Type2),
            "iso_27001_2022" | "iso27001" | "iso" => Some(ComplianceFramework::Iso27001),
            "cis_controls_v8" | "cis" | "cis_v8" => Some(ComplianceFramework::CisControlsV8),
            "hipaa_security" | "hipaa" => Some(ComplianceFramework::HipaaSecurity),
            "pci_dss_v4" | "pci" | "pci_dss" => Some(ComplianceFramework::PciDssV4),
            _ => None,
        }
    }
}

impl fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    Compliant,
    PartiallyCompliant,
    NonCompliant,
    NotApplicable,
}

impl ComplianceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ComplianceStatus::Compliant => "compliant",
            ComplianceStatus::PartiallyCompliant => "partially_compliant",
            ComplianceStatus::NonCompliant => "non_compliant",
            ComplianceStatus::NotApplicable => "not_applicable",
        }
    }

    pub fn parse_status(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "compliant" => Some(ComplianceStatus::Compliant),
            "partially_compliant" | "partial" => Some(ComplianceStatus::PartiallyCompliant),
            "non_compliant" | "noncompliant" => Some(ComplianceStatus::NonCompliant),
            "not_applicable" | "na" => Some(ComplianceStatus::NotApplicable),
            _ => None,
        }
    }

    pub fn can_transition_to(&self, next: ComplianceStatus) -> bool {
        match (self, next) {
            (s, n) if *s == n => true,
            (ComplianceStatus::NonCompliant, ComplianceStatus::PartiallyCompliant) => true,
            (ComplianceStatus::NonCompliant, ComplianceStatus::Compliant) => true,
            (ComplianceStatus::NonCompliant, ComplianceStatus::NotApplicable) => true,
            (ComplianceStatus::PartiallyCompliant, ComplianceStatus::Compliant) => true,
            (ComplianceStatus::PartiallyCompliant, ComplianceStatus::NonCompliant) => true,
            (ComplianceStatus::Compliant, ComplianceStatus::PartiallyCompliant) => true,
            (ComplianceStatus::Compliant, ComplianceStatus::NonCompliant) => true,
            (ComplianceStatus::NotApplicable, ComplianceStatus::NonCompliant) => true,
            (ComplianceStatus::NotApplicable, ComplianceStatus::Compliant) => true,
            _ => true,
        }
    }
}

impl fmt::Display for ComplianceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubstrateTargetType {
    PepGate,
    CapabilityToken,
    AuditRing,
    ThreatMitigation,
    ConstitutionRule,
}

impl SubstrateTargetType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SubstrateTargetType::PepGate => "pep_gate",
            SubstrateTargetType::CapabilityToken => "capability_token",
            SubstrateTargetType::AuditRing => "audit_ring",
            SubstrateTargetType::ThreatMitigation => "threat_mitigation",
            SubstrateTargetType::ConstitutionRule => "constitution_rule",
        }
    }

    pub fn parse_target_type(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "pep_gate" | "pep" => Some(SubstrateTargetType::PepGate),
            "capability_token" | "capability" | "token" => Some(SubstrateTargetType::CapabilityToken),
            "audit_ring" | "audit" => Some(SubstrateTargetType::AuditRing),
            "threat_mitigation" | "threat" | "mitigation" => Some(SubstrateTargetType::ThreatMitigation),
            "constitution_rule" | "rule" => Some(SubstrateTargetType::ConstitutionRule),
            _ => None,
        }
    }
}

impl fmt::Display for SubstrateTargetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceControl {
    pub id: String,
    pub framework: ComplianceFramework,
    pub title: String,
    pub description: String,
    pub category: String,
}

impl ComplianceControl {
    pub fn new(id: &str, framework: ComplianceFramework, title: &str, description: &str, category: &str) -> Result<Self, String> {
        validate_identifier(id, "Control ID")?;
        validate_title(title, "Control title")?;
        validate_text_length(description, MAX_COMPLIANCE_DESC_LEN, "Control description")?;
        validate_text_length(category, MAX_COMPLIANCE_TITLE_LEN, "Control category")?;

        Ok(Self {
            id: id.to_string(),
            framework,
            title: title.to_string(),
            description: description.to_string(),
            category: category.to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceMappingEntry {
    pub id: String,
    pub control_id: String,
    pub framework: ComplianceFramework,
    pub target_type: SubstrateTargetType,
    pub target_ref: String,
    pub threat_ids: Vec<String>,
    pub status: ComplianceStatus,
    pub mitigation_summary: String,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl ComplianceMappingEntry {
    pub fn new(
        id: &str,
        control_id: &str,
        framework: ComplianceFramework,
        target_type: SubstrateTargetType,
        target_ref: &str,
        threat_ids: Vec<String>,
        status: ComplianceStatus,
        mitigation_summary: &str,
        tags: Vec<String>,
    ) -> Result<Self, String> {
        validate_identifier(id, "Mapping ID")?;
        validate_identifier(control_id, "Control ID")?;
        if target_ref.trim().is_empty() {
            return Err(format!("{}: Substrate target ref cannot be empty", COMPLIANCE_ERR_MISSING_SUBSTRATE_REF));
        }
        validate_text_length(target_ref, MAX_COMPLIANCE_ID_LEN, "Substrate target ref")?;
        validate_text_length(mitigation_summary, MAX_COMPLIANCE_NOTES_LEN, "Mitigation summary")?;

        if status == ComplianceStatus::Compliant && mitigation_summary.trim().is_empty() {
            return Err(format!("{}: Status 'compliant' requires a non-empty mitigation summary", COMPLIANCE_ERR_BOUNDS_EXCEEDED));
        }

        if threat_ids.len() > MAX_THREAT_IDS_COUNT {
            return Err(format!("{}: Threat IDs count exceeds maximum {}", COMPLIANCE_ERR_BOUNDS_EXCEEDED, MAX_THREAT_IDS_COUNT));
        }
        for tid in &threat_ids {
            validate_identifier(tid, "Threat ID")?;
        }

        if tags.len() > MAX_TAGS_COUNT {
            return Err(format!("{}: Tags count exceeds maximum {}", COMPLIANCE_ERR_BOUNDS_EXCEEDED, MAX_TAGS_COUNT));
        }
        for tag in &tags {
            validate_identifier(tag, "Tag")?;
        }

        let now = utcnow_iso();
        Ok(Self {
            id: id.to_string(),
            control_id: control_id.to_string(),
            framework,
            target_type,
            target_ref: target_ref.to_string(),
            threat_ids,
            status,
            mitigation_summary: mitigation_summary.to_string(),
            tags,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn transition_to(&mut self, next: ComplianceStatus, reason: &str) -> Result<(), String> {
        if !self.status.can_transition_to(next) {
            return Err(format!("{}: Cannot transition from {} to {}", COMPLIANCE_ERR_INVALID_STATUS_TRANSITION, self.status, next));
        }
        if next == ComplianceStatus::Compliant && self.mitigation_summary.trim().is_empty() && reason.trim().is_empty() {
            return Err(format!("{}: Cannot transition to compliant without mitigation summary or reason", COMPLIANCE_ERR_BOUNDS_EXCEEDED));
        }
        self.status = next;
        self.updated_at = utcnow_iso();
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceCatalogSnapshot {
    pub version: String,
    pub mappings: Vec<ComplianceMappingEntry>,
    pub generated_at: String,
}

impl ComplianceCatalogSnapshot {
    pub fn new(version: &str) -> Self {
        Self {
            version: version.to_string(),
            mappings: Vec::new(),
            generated_at: utcnow_iso(),
        }
    }

    pub fn canonical_baseline() -> Self {
        let mut snap = Self::new("1.0.0");
        let baseline = vec![
            ComplianceMappingEntry::new(
                "MAP-NIST-AC3-PEP",
                "AC-3",
                ComplianceFramework::NistSp80053Rev5,
                SubstrateTargetType::PepGate,
                "pep_enforce_gate",
                vec!["T-EOP-001".to_string()],
                ComplianceStatus::Compliant,
                "Enforced via AIOS Security Kernel PEP gate validation on all syscalls and capability invocations.",
                vec!["access_control".to_string(), "kernel".to_string()],
            ).unwrap(),
            ComplianceMappingEntry::new(
                "MAP-NIST-AU2-RING",
                "AU-2",
                ComplianceFramework::NistSp80053Rev5,
                SubstrateTargetType::AuditRing,
                "audit_ring_commit",
                vec!["T-REP-001".to_string()],
                ComplianceStatus::Compliant,
                "Append-only SHA-256 hash-chained SQLite WAL audit ring records consequential security events.",
                vec!["audit".to_string(), "wal".to_string()],
            ).unwrap(),
            ComplianceMappingEntry::new(
                "MAP-SOC2-CC61-PEP",
                "CC6.1",
                ComplianceFramework::Soc2Type2,
                SubstrateTargetType::PepGate,
                "capability_grant_gate",
                vec!["T-EOP-002".to_string()],
                ComplianceStatus::Compliant,
                "Access rights restricted using bounded cryptographic capability tokens.",
                vec!["soc2".to_string(), "capabilities".to_string()],
            ).unwrap(),
            ComplianceMappingEntry::new(
                "MAP-CIS-CTRL6-PEP",
                "CIS-6",
                ComplianceFramework::CisControlsV8,
                SubstrateTargetType::ConstitutionRule,
                "R-01",
                vec!["T-EOP-001".to_string()],
                ComplianceStatus::Compliant,
                "Access Control Management governed by Constitution Rules and PEP gating.",
                vec!["cis".to_string(), "constitution".to_string()],
            ).unwrap(),
        ];
        snap.mappings = baseline;
        snap
    }

    pub fn add_mapping(&mut self, entry: ComplianceMappingEntry) -> Result<(), String> {
        if self.mappings.len() >= MAX_COMPLIANCE_ENTRIES_CAPACITY {
            return Err(format!("{}: Catalog capacity exceeded", COMPLIANCE_ERR_BOUNDS_EXCEEDED));
        }
        if self.mappings.iter().any(|m| m.id == entry.id) {
            return Err(format!("{}: Duplicate mapping ID {}", COMPLIANCE_ERR_DUPLICATE_ID, entry.id));
        }
        self.mappings.push(entry);
        self.generated_at = utcnow_iso();
        Ok(())
    }

    pub fn get_mapping(&self, id: &str) -> Option<&ComplianceMappingEntry> {
        self.mappings.iter().find(|m| m.id == id)
    }

    pub fn get_mapping_mut(&mut self, id: &str) -> Option<&mut ComplianceMappingEntry> {
        self.mappings.iter_mut().find(|m| m.id == id)
    }

    pub fn remove_mapping(&mut self, id: &str) -> Option<ComplianceMappingEntry> {
        if let Some(pos) = self.mappings.iter().position(|m| m.id == id) {
            let removed = self.mappings.remove(pos);
            self.generated_at = utcnow_iso();
            Some(removed)
        } else {
            None
        }
    }

    pub fn find_by_framework(&self, framework: ComplianceFramework) -> Vec<&ComplianceMappingEntry> {
        self.mappings.iter().filter(|m| m.framework == framework).collect()
    }

    pub fn find_by_control(&self, control_id: &str) -> Vec<&ComplianceMappingEntry> {
        self.mappings.iter().filter(|m| m.control_id == control_id).collect()
    }

    pub fn find_by_target(&self, target_ref: &str) -> Vec<&ComplianceMappingEntry> {
        self.mappings.iter().filter(|m| m.target_ref == target_ref).collect()
    }

    pub fn find_by_status(&self, status: ComplianceStatus) -> Vec<&ComplianceMappingEntry> {
        self.mappings.iter().filter(|m| m.status == status).collect()
    }

    pub fn compliance_ratio(&self) -> f64 {
        if self.mappings.is_empty() {
            return 1.0;
        }
        let compliant_count = self.mappings.iter().filter(|m| m.status == ComplianceStatus::Compliant).count();
        compliant_count as f64 / self.mappings.len() as f64
    }
}

pub fn validate_identifier(id: &str, field_name: &str) -> Result<(), String> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(format!("{}: {} cannot be empty", COMPLIANCE_ERR_INVALID_ID, field_name));
    }
    if trimmed.len() > MAX_COMPLIANCE_ID_LEN {
        return Err(format!("{}: {} exceeds maximum length {}", COMPLIANCE_ERR_BOUNDS_EXCEEDED, field_name, MAX_COMPLIANCE_ID_LEN));
    }
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return Err(format!("{}: {} contains invalid characters (allowed: alphanumeric, '_', '-', '.')", COMPLIANCE_ERR_INVALID_ID, field_name));
    }
    Ok(())
}

pub fn validate_title(title: &str, field_name: &str) -> Result<(), String> {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return Err(format!("{}: {} cannot be empty", COMPLIANCE_ERR_INVALID_TITLE, field_name));
    }
    if trimmed.len() > MAX_COMPLIANCE_TITLE_LEN {
        return Err(format!("{}: {} exceeds maximum length {}", COMPLIANCE_ERR_BOUNDS_EXCEEDED, field_name, MAX_COMPLIANCE_TITLE_LEN));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(format!("{}: {} contains forbidden control characters", COMPLIANCE_ERR_CONTROL_CHARS, field_name));
    }
    Ok(())
}

pub fn validate_text_length(text: &str, max_len: usize, field_name: &str) -> Result<(), String> {
    if text.len() > max_len {
        return Err(format!("{}: {} exceeds maximum length {}", COMPLIANCE_ERR_BOUNDS_EXCEEDED, field_name, max_len));
    }
    if text.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
        return Err(format!("{}: {} contains forbidden control characters", COMPLIANCE_ERR_CONTROL_CHARS, field_name));
    }
    Ok(())
}
