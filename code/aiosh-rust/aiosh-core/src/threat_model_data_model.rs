//! Threat Model Maintenance Data Model (THREAT1..THREAT5).
//!
//! Provides the formal domain primitives, STRIDE categories, risk scoring tiers,
//! and lifecycle state transitions for the AIOS threat catalog.

use std::fmt;
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatModelSnapshot {
    pub version: String,
    pub threats: Vec<ThreatEntry>,
    pub generated_at: String,
}
