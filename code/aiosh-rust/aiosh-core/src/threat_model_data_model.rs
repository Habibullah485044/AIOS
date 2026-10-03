//! Threat Model Maintenance Data Model (THREAT1..THREAT5).
//!
//! Provides the formal domain primitives, STRIDE categories, risk scoring tiers,
//! and lifecycle state transitions for the AIOS threat catalog.

use std::fmt;
use serde::{Deserialize, Serialize};
use crate::canonical::utcnow_iso;

pub const MAX_THREAT_ID_LEN: usize = 64;
pub const MAX_THREAT_TITLE_LEN: usize = 128;
pub const MAX_THREAT_DESC_LEN: usize = 2048;
pub const MAX_THREAT_MITIGATION_LEN: usize = 2048;
pub const MAX_CWE_COUNT: usize = 16;
pub const MAX_MITIGATIONS_COUNT: usize = 16;

pub const THREAT_ERR_INVALID_ID: &str = "THREAT_ERR_INVALID_ID";
pub const THREAT_ERR_INVALID_TITLE: &str = "THREAT_ERR_INVALID_TITLE";
pub const THREAT_ERR_BOUNDS_EXCEEDED: &str = "THREAT_ERR_BOUNDS_EXCEEDED";
pub const THREAT_ERR_INVALID_TRANSITION: &str = "THREAT_ERR_INVALID_TRANSITION";
pub const THREAT_ERR_CONTROL_CHARS: &str = "THREAT_ERR_CONTROL_CHARS";
pub const THREAT_ERR_DUPLICATE_ID: &str = "THREAT_ERR_DUPLICATE_ID";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    Spoofing,
    Tampering,
    Repudiation,
    InformationDisclosure,
    DenialOfService,
    ElevationOfPrivilege,
    SupplyChainRisk,
}

impl ThreatCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatCategory::Spoofing => "spoofing",
            ThreatCategory::Tampering => "tampering",
            ThreatCategory::Repudiation => "repudiation",
            ThreatCategory::InformationDisclosure => "information_disclosure",
            ThreatCategory::DenialOfService => "denial_of_service",
            ThreatCategory::ElevationOfPrivilege => "elevation_of_privilege",
            ThreatCategory::SupplyChainRisk => "supply_chain_risk",
        }
    }

    pub fn parse_category(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "spoofing" => Some(ThreatCategory::Spoofing),
            "tampering" => Some(ThreatCategory::Tampering),
            "repudiation" => Some(ThreatCategory::Repudiation),
            "information_disclosure" | "disclosure" => Some(ThreatCategory::InformationDisclosure),
            "denial_of_service" | "dos" => Some(ThreatCategory::DenialOfService),
            "elevation_of_privilege" | "privilege_elevation" | "eop" => Some(ThreatCategory::ElevationOfPrivilege),
            "supply_chain_risk" | "supply_chain" => Some(ThreatCategory::SupplyChainRisk),
            _ => None,
        }
    }
}

impl fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSeverity {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl ThreatSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatSeverity::Low => "low",
            ThreatSeverity::Medium => "medium",
            ThreatSeverity::High => "high",
            ThreatSeverity::Critical => "critical",
        }
    }

    pub fn parse_severity(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(ThreatSeverity::Low),
            "medium" | "med" => Some(ThreatSeverity::Medium),
            "high" => Some(ThreatSeverity::High),
            "critical" | "crit" => Some(ThreatSeverity::Critical),
            _ => None,
        }
    }

    pub fn score(&self) -> u8 {
        *self as u8
    }
}

impl fmt::Display for ThreatSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatStatus {
    Identified,
    UnderReview,
    Mitigated,
    Accepted,
    Resolved,
}

impl ThreatStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatStatus::Identified => "identified",
            ThreatStatus::UnderReview => "under_review",
            ThreatStatus::Mitigated => "mitigated",
            ThreatStatus::Accepted => "accepted",
            ThreatStatus::Resolved => "resolved",
        }
    }

    pub fn parse_status(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "identified" => Some(ThreatStatus::Identified),
            "under_review" | "review" => Some(ThreatStatus::UnderReview),
            "mitigated" => Some(ThreatStatus::Mitigated),
            "accepted" => Some(ThreatStatus::Accepted),
            "resolved" => Some(ThreatStatus::Resolved),
            _ => None,
        }
    }

    pub fn can_transition_to(&self, next: ThreatStatus) -> bool {
        match (self, next) {
            (s, n) if *s == n => true,
            (ThreatStatus::Identified, ThreatStatus::UnderReview) => true,
            (ThreatStatus::Identified, ThreatStatus::Mitigated) => true,
            (ThreatStatus::Identified, ThreatStatus::Accepted) => true,
            (ThreatStatus::UnderReview, ThreatStatus::Mitigated) => true,
            (ThreatStatus::UnderReview, ThreatStatus::Accepted) => true,
            (ThreatStatus::UnderReview, ThreatStatus::Identified) => true,
            (ThreatStatus::Mitigated, ThreatStatus::Resolved) => true,
            (ThreatStatus::Mitigated, ThreatStatus::Identified) => true,
            (ThreatStatus::Accepted, ThreatStatus::UnderReview) => true,
            (ThreatStatus::Accepted, ThreatStatus::Resolved) => true,
            (ThreatStatus::Resolved, ThreatStatus::Identified) => true,
            _ => false,
        }
    }
}

impl fmt::Display for ThreatStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatEntry {
    pub id: String,
    pub title: String,
    pub description: String,
    pub category: ThreatCategory,
    pub severity: ThreatSeverity,
    pub status: ThreatStatus,
    pub component: String,
    pub cwe_ids: Vec<String>,
    pub mitigations: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl ThreatEntry {
    pub fn validate_id(id: &str) -> Result<(), String> {
        let trimmed = id.trim();
        if trimmed.is_empty() {
            return Err(format!("{}: Threat ID cannot be empty", THREAT_ERR_INVALID_ID));
        }
        if trimmed.len() > MAX_THREAT_ID_LEN {
            return Err(format!("{}: Threat ID exceeds max length {}", THREAT_ERR_BOUNDS_EXCEEDED, MAX_THREAT_ID_LEN));
        }
        if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            return Err(format!("{}: Threat ID contains forbidden characters (must be alphanumeric, '_' or '-')", THREAT_ERR_INVALID_ID));
        }
        Ok(())
    }

    pub fn validate_title(title: &str) -> Result<(), String> {
        let trimmed = title.trim();
        if trimmed.is_empty() {
            return Err(format!("{}: Threat title cannot be empty", THREAT_ERR_INVALID_TITLE));
        }
        if trimmed.len() > MAX_THREAT_TITLE_LEN {
            return Err(format!("{}: Threat title exceeds max length {}", THREAT_ERR_BOUNDS_EXCEEDED, MAX_THREAT_TITLE_LEN));
        }
        if trimmed.chars().any(|c| c.is_control()) {
            return Err(format!("{}: Threat title contains forbidden control characters", THREAT_ERR_CONTROL_CHARS));
        }
        Ok(())
    }

    pub fn validate_description(desc: &str) -> Result<(), String> {
        if desc.len() > MAX_THREAT_DESC_LEN {
            return Err(format!("{}: Threat description exceeds max length {}", THREAT_ERR_BOUNDS_EXCEEDED, MAX_THREAT_DESC_LEN));
        }
        if desc.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
            return Err(format!("{}: Threat description contains forbidden control characters", THREAT_ERR_CONTROL_CHARS));
        }
        if desc.contains("BEGIN PRIVATE KEY") || desc.contains("BEGIN RSA PRIVATE KEY") {
            return Err(format!("{}: Secret or private key material detected in threat description", THREAT_ERR_BOUNDS_EXCEEDED));
        }
        Ok(())
    }

    pub fn new(
        id: &str,
        title: &str,
        description: &str,
        category: ThreatCategory,
        severity: ThreatSeverity,
        component: &str,
        cwe_ids: Vec<String>,
        mitigations: Vec<String>,
    ) -> Result<Self, String> {
        Self::validate_id(id)?;
        Self::validate_title(title)?;
        Self::validate_description(description)?;

        if cwe_ids.len() > MAX_CWE_COUNT {
            return Err(format!("{}: CWE IDs count exceeds max {}", THREAT_ERR_BOUNDS_EXCEEDED, MAX_CWE_COUNT));
        }
        for cwe in &cwe_ids {
            if cwe.chars().any(|c| c.is_control()) || cwe.len() > 32 {
                return Err(format!("{}: Invalid CWE identifier '{}'", THREAT_ERR_CONTROL_CHARS, cwe));
            }
        }

        if mitigations.len() > MAX_MITIGATIONS_COUNT {
            return Err(format!("{}: Mitigations count exceeds max {}", THREAT_ERR_BOUNDS_EXCEEDED, MAX_MITIGATIONS_COUNT));
        }
        for m in &mitigations {
            if m.len() > MAX_THREAT_MITIGATION_LEN || m.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
                return Err(format!("{}: Invalid mitigation text", THREAT_ERR_BOUNDS_EXCEEDED));
            }
        }

        let now = utcnow_iso();
        Ok(Self {
            id: id.trim().to_string(),
            title: title.trim().to_string(),
            description: description.trim().to_string(),
            category,
            severity,
            status: ThreatStatus::Identified,
            component: component.trim().to_string(),
            cwe_ids,
            mitigations,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub fn transition_to(&mut self, next_status: ThreatStatus) -> Result<(), String> {
        if !self.status.can_transition_to(next_status) {
            return Err(format!(
                "{}: Cannot transition from '{}' to '{}'",
                THREAT_ERR_INVALID_TRANSITION,
                self.status,
                next_status
            ));
        }
        if next_status == ThreatStatus::Mitigated && self.mitigations.is_empty() {
            return Err(format!(
                "{}: Cannot transition to 'mitigated' without at least one mitigation recorded",
                THREAT_ERR_INVALID_TRANSITION
            ));
        }
        self.status = next_status;
        self.updated_at = utcnow_iso();
        Ok(())
    }

    pub fn add_mitigation(&mut self, mitigation: &str) -> Result<(), String> {
        let trimmed = mitigation.trim();
        if trimmed.is_empty() {
            return Err(format!("{}: Mitigation cannot be empty", THREAT_ERR_BOUNDS_EXCEEDED));
        }
        if trimmed.len() > MAX_THREAT_MITIGATION_LEN {
            return Err(format!("{}: Mitigation exceeds max length {}", THREAT_ERR_BOUNDS_EXCEEDED, MAX_THREAT_MITIGATION_LEN));
        }
        if trimmed.contains("BEGIN PRIVATE KEY") || trimmed.contains("BEGIN RSA PRIVATE KEY") {
            return Err(format!("{}: Secret or private key material detected in mitigation", THREAT_ERR_BOUNDS_EXCEEDED));
        }
        if self.mitigations.len() >= MAX_MITIGATIONS_COUNT {
            return Err(format!("{}: Mitigations count reached max {}", THREAT_ERR_BOUNDS_EXCEEDED, MAX_MITIGATIONS_COUNT));
        }
        if !self.mitigations.iter().any(|m| m == trimmed) {
            self.mitigations.push(trimmed.to_string());
            self.updated_at = utcnow_iso();
        }
        Ok(())
    }

    pub fn add_cwe(&mut self, cwe: &str) -> Result<(), String> {
        let trimmed = cwe.trim();
        if trimmed.is_empty() || trimmed.len() > 32 {
            return Err(format!("{}: Invalid CWE identifier", THREAT_ERR_BOUNDS_EXCEEDED));
        }
        if self.cwe_ids.len() >= MAX_CWE_COUNT {
            return Err(format!("{}: CWE list reached max count {}", THREAT_ERR_BOUNDS_EXCEEDED, MAX_CWE_COUNT));
        }
        if !self.cwe_ids.iter().any(|c| c == trimmed) {
            self.cwe_ids.push(trimmed.to_string());
            self.updated_at = utcnow_iso();
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatModelSnapshot {
    pub version: String,
    pub threats: Vec<ThreatEntry>,
    pub generated_at: String,
}

impl ThreatModelSnapshot {
    pub fn new(version: &str) -> Self {
        Self {
            version: version.to_string(),
            threats: Vec::new(),
            generated_at: utcnow_iso(),
        }
    }

    pub fn add_entry(&mut self, entry: ThreatEntry) -> Result<(), String> {
        if self.threats.iter().any(|t| t.id == entry.id) {
            return Err(format!("{}: Threat with ID '{}' already exists", THREAT_ERR_DUPLICATE_ID, entry.id));
        }
        self.threats.push(entry);
        self.generated_at = utcnow_iso();
        Ok(())
    }

    pub fn get_entry(&self, id: &str) -> Option<&ThreatEntry> {
        self.threats.iter().find(|t| t.id == id)
    }

    pub fn get_entry_mut(&mut self, id: &str) -> Option<&mut ThreatEntry> {
        self.threats.iter_mut().find(|t| t.id == id)
    }

    pub fn filter_by_category(&self, cat: ThreatCategory) -> Vec<&ThreatEntry> {
        self.threats.iter().filter(|t| t.category == cat).collect()
    }

    pub fn filter_by_severity(&self, min_sev: ThreatSeverity) -> Vec<&ThreatEntry> {
        self.threats.iter().filter(|t| t.severity >= min_sev).collect()
    }

    pub fn filter_by_status(&self, status: ThreatStatus) -> Vec<&ThreatEntry> {
        self.threats.iter().filter(|t| t.status == status).collect()
    }
}
