//! Incident Response Runbooks Data Model (IR-INV1..IR-INV5).
//!
//! Provides the formal domain primitives, severity taxonomy, incident categories,
//! execution phases, substrate target bindings, and catalog snapshots for AIOS Incident Response Runbooks.

use std::fmt;
use serde::{Deserialize, Serialize};
use crate::canonical::utcnow_iso;

pub const MAX_RUNBOOK_ID_LEN: usize = 64;
pub const MAX_RUNBOOK_TITLE_LEN: usize = 128;
pub const MAX_RUNBOOK_DESC_LEN: usize = 2048;
pub const MAX_RUNBOOK_STEPS_COUNT: usize = 32;
pub const MAX_RUNBOOK_TAGS_COUNT: usize = 16;
pub const MAX_RUNBOOK_CATALOG_CAPACITY: usize = 256;

pub const RUNBOOK_ERR_INVALID_ID: &str = "RUNBOOK_ERR_INVALID_ID";
pub const RUNBOOK_ERR_INVALID_TITLE: &str = "RUNBOOK_ERR_INVALID_TITLE";
pub const RUNBOOK_ERR_BOUNDS_EXCEEDED: &str = "RUNBOOK_ERR_BOUNDS_EXCEEDED";
pub const RUNBOOK_ERR_CONTROL_CHARS: &str = "RUNBOOK_ERR_CONTROL_CHARS";
pub const RUNBOOK_ERR_DUPLICATE_ID: &str = "RUNBOOK_ERR_DUPLICATE_ID";
pub const RUNBOOK_ERR_EMPTY_STEPS: &str = "RUNBOOK_ERR_EMPTY_STEPS";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl IncidentSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            IncidentSeverity::Low => "low",
            IncidentSeverity::Medium => "medium",
            IncidentSeverity::High => "high",
            IncidentSeverity::Critical => "critical",
        }
    }

    pub fn parse_severity(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(IncidentSeverity::Low),
            "medium" | "med" => Some(IncidentSeverity::Medium),
            "high" => Some(IncidentSeverity::High),
            "critical" | "crit" => Some(IncidentSeverity::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for IncidentSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentCategory {
    MalwareContainment,
    UnauthorizedAccess,
    DataExfiltration,
    DenialOfService,
    IntegrityViolation,
    PolicyBypassAttempt,
}

impl IncidentCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            IncidentCategory::MalwareContainment => "malware_containment",
            IncidentCategory::UnauthorizedAccess => "unauthorized_access",
            IncidentCategory::DataExfiltration => "data_exfiltration",
            IncidentCategory::DenialOfService => "denial_of_service",
            IncidentCategory::IntegrityViolation => "integrity_violation",
            IncidentCategory::PolicyBypassAttempt => "policy_bypass_attempt",
        }
    }

    pub fn parse_category(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "malware_containment" | "malware" => Some(IncidentCategory::MalwareContainment),
            "unauthorized_access" | "access" => Some(IncidentCategory::UnauthorizedAccess),
            "data_exfiltration" | "exfiltration" => Some(IncidentCategory::DataExfiltration),
            "denial_of_service" | "dos" => Some(IncidentCategory::DenialOfService),
            "integrity_violation" | "integrity" => Some(IncidentCategory::IntegrityViolation),
            "policy_bypass_attempt" | "bypass" => Some(IncidentCategory::PolicyBypassAttempt),
            _ => None,
        }
    }
}

impl fmt::Display for IncidentCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookPhase {
    Preparation,
    Detection,
    Containment,
    Eradication,
    Recovery,
    PostIncident,
}

impl RunbookPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            RunbookPhase::Preparation => "preparation",
            RunbookPhase::Detection => "detection",
            RunbookPhase::Containment => "containment",
            RunbookPhase::Eradication => "eradication",
            RunbookPhase::Recovery => "recovery",
            RunbookPhase::PostIncident => "post_incident",
        }
    }

    pub fn parse_phase(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "preparation" | "prep" => Some(RunbookPhase::Preparation),
            "detection" | "detect" => Some(RunbookPhase::Detection),
            "containment" | "contain" => Some(RunbookPhase::Containment),
            "eradication" | "eradicate" => Some(RunbookPhase::Eradication),
            "recovery" | "recover" => Some(RunbookPhase::Recovery),
            "post_incident" | "post" => Some(RunbookPhase::PostIncident),
            _ => None,
        }
    }
}

impl fmt::Display for RunbookPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookTargetSubstrate {
    Process,
    Network,
    Identity,
    AuditRing,
    Storage,
}

impl RunbookTargetSubstrate {
    pub fn as_str(&self) -> &'static str {
        match self {
            RunbookTargetSubstrate::Process => "process",
            RunbookTargetSubstrate::Network => "network",
            RunbookTargetSubstrate::Identity => "identity",
            RunbookTargetSubstrate::AuditRing => "audit_ring",
            RunbookTargetSubstrate::Storage => "storage",
        }
    }

    pub fn parse_target(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "process" | "proc" => Some(RunbookTargetSubstrate::Process),
            "network" | "net" => Some(RunbookTargetSubstrate::Network),
            "identity" | "id" | "token" => Some(RunbookTargetSubstrate::Identity),
            "audit_ring" | "audit" | "ring" => Some(RunbookTargetSubstrate::AuditRing),
            "storage" | "disk" | "fs" => Some(RunbookTargetSubstrate::Storage),
            _ => None,
        }
    }
}

impl fmt::Display for RunbookTargetSubstrate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookStep {
    pub id: String,
    pub title: String,
    pub phase: RunbookPhase,
    pub target: RunbookTargetSubstrate,
    pub action_template: String,
    pub automated: bool,
    pub requires_confirmation: bool,
    pub timeout_seconds: u64,
}

impl RunbookStep {
    pub fn new(
        id: &str,
        title: &str,
        phase: RunbookPhase,
        target: RunbookTargetSubstrate,
        action_template: &str,
        automated: bool,
        requires_confirmation: bool,
        timeout_seconds: u64,
    ) -> Result<Self, String> {
        validate_identifier(id, "Step ID")?;
        validate_title(title, "Step title")?;
        validate_text_length(action_template, MAX_RUNBOOK_DESC_LEN, "Action template")?;

        Ok(Self {
            id: id.to_string(),
            title: title.to_string(),
            phase,
            target,
            action_template: action_template.to_string(),
            automated,
            requires_confirmation,
            timeout_seconds: if timeout_seconds == 0 { 30 } else { timeout_seconds },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookSpec {
    pub id: String,
    pub title: String,
    pub category: IncidentCategory,
    pub severity: IncidentSeverity,
    pub description: String,
    pub steps: Vec<RunbookStep>,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl RunbookSpec {
    pub fn new(
        id: &str,
        title: &str,
        category: IncidentCategory,
        severity: IncidentSeverity,
        description: &str,
        steps: Vec<RunbookStep>,
        tags: Vec<String>,
    ) -> Result<Self, String> {
        validate_identifier(id, "Runbook ID")?;
        validate_title(title, "Runbook title")?;
        validate_text_length(description, MAX_RUNBOOK_DESC_LEN, "Runbook description")?;

        if steps.is_empty() {
            return Err(format!("{}: Runbook must contain at least one step", RUNBOOK_ERR_EMPTY_STEPS));
        }
        if steps.len() > MAX_RUNBOOK_STEPS_COUNT {
            return Err(format!("{}: Steps count exceeds maximum allowed {}", RUNBOOK_ERR_BOUNDS_EXCEEDED, MAX_RUNBOOK_STEPS_COUNT));
        }

        if tags.len() > MAX_RUNBOOK_TAGS_COUNT {
            return Err(format!("{}: Tags count exceeds maximum allowed {}", RUNBOOK_ERR_BOUNDS_EXCEEDED, MAX_RUNBOOK_TAGS_COUNT));
        }
        for tag in &tags {
            validate_identifier(tag, "Tag")?;
        }

        let now = utcnow_iso();
        Ok(Self {
            id: id.to_string(),
            title: title.to_string(),
            category,
            severity,
            description: description.to_string(),
            steps,
            tags,
            created_at: now.clone(),
            updated_at: now,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookCatalogSnapshot {
    pub version: String,
    pub runbooks: Vec<RunbookSpec>,
    pub generated_at: String,
}

impl RunbookCatalogSnapshot {
    pub fn new(version: &str) -> Self {
        Self {
            version: version.to_string(),
            runbooks: Vec::new(),
            generated_at: utcnow_iso(),
        }
    }

    pub fn canonical_baseline() -> Self {
        let mut snap = Self::new("1.0.0");
        let malware_steps = vec![
            RunbookStep::new(
                "STEP-MW-01",
                "Freeze target malicious process via cgroup/SIGSTOP",
                RunbookPhase::Containment,
                RunbookTargetSubstrate::Process,
                "aiosh run kill -STOP {target_pid}",
                true,
                false,
                15,
            ).unwrap(),
            RunbookStep::new(
                "STEP-MW-02",
                "Quarantine network interface and drop outbound connections",
                RunbookPhase::Containment,
                RunbookTargetSubstrate::Network,
                "aiosh run iptables -A OUTPUT -m owner --uid-owner {target_uid} -j DROP",
                true,
                false,
                30,
            ).unwrap(),
            RunbookStep::new(
                "STEP-MW-03",
                "Commit forensic state snapshot to append-only audit ring",
                RunbookPhase::PostIncident,
                RunbookTargetSubstrate::AuditRing,
                "aiosh audit checkpoint --reason 'Malware containment forensic snapshot'",
                true,
                false,
                10,
            ).unwrap(),
        ];

        let access_steps = vec![
            RunbookStep::new(
                "STEP-UA-01",
                "Revoke active capability tokens for compromised actor",
                RunbookPhase::Containment,
                RunbookTargetSubstrate::Identity,
                "aiosh grant revoke {grant_id}",
                true,
                false,
                10,
            ).unwrap(),
            RunbookStep::new(
                "STEP-UA-02",
                "Terminate unauthorized operator session",
                RunbookPhase::Containment,
                RunbookTargetSubstrate::Identity,
                "aiosh session terminate {session_id}",
                true,
                true,
                30,
            ).unwrap(),
        ];

        let baseline = vec![
            RunbookSpec::new(
                "RB-IR-MALWARE-01",
                "Rapid Malware Containment & Process Freeze",
                IncidentCategory::MalwareContainment,
                IncidentSeverity::High,
                "Emergency containment protocol for suspicious execution or active malware.",
                malware_steps,
                vec!["malware".to_string(), "emergency".to_string(), "containment".to_string()],
            ).unwrap(),
            RunbookSpec::new(
                "RB-IR-ACCESS-01",
                "Unauthorized Access Remediation & Token Revocation",
                IncidentCategory::UnauthorizedAccess,
                IncidentSeverity::Critical,
                "Immediate revocation and eviction protocol following unauthorized credential access.",
                access_steps,
                vec!["access".to_string(), "token".to_string(), "eviction".to_string()],
            ).unwrap(),
        ];

        snap.runbooks = baseline;
        snap
    }

    pub fn add_runbook(&mut self, runbook: RunbookSpec) -> Result<(), String> {
        if self.runbooks.len() >= MAX_RUNBOOK_CATALOG_CAPACITY {
            return Err(format!("{}: Runbook catalog capacity exceeded", RUNBOOK_ERR_BOUNDS_EXCEEDED));
        }
        if self.runbooks.iter().any(|r| r.id == runbook.id) {
            return Err(format!("{}: Duplicate runbook ID {}", RUNBOOK_ERR_DUPLICATE_ID, runbook.id));
        }
        self.runbooks.push(runbook);
        self.generated_at = utcnow_iso();
        Ok(())
    }

    pub fn get_runbook(&self, id: &str) -> Option<&RunbookSpec> {
        self.runbooks.iter().find(|r| r.id == id)
    }

    pub fn get_runbook_mut(&mut self, id: &str) -> Option<&mut RunbookSpec> {
        self.runbooks.iter_mut().find(|r| r.id == id)
    }

    pub fn remove_runbook(&mut self, id: &str) -> Option<RunbookSpec> {
        if let Some(pos) = self.runbooks.iter().position(|r| r.id == id) {
            let removed = self.runbooks.remove(pos);
            self.generated_at = utcnow_iso();
            Some(removed)
        } else {
            None
        }
    }

    pub fn find_by_category(&self, category: IncidentCategory) -> Vec<&RunbookSpec> {
        self.runbooks.iter().filter(|r| r.category == category).collect()
    }

    pub fn find_by_severity(&self, severity: IncidentSeverity) -> Vec<&RunbookSpec> {
        self.runbooks.iter().filter(|r| r.severity == severity).collect()
    }
}

pub fn validate_identifier(id: &str, field_name: &str) -> Result<(), String> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(format!("{}: {} cannot be empty", RUNBOOK_ERR_INVALID_ID, field_name));
    }
    if trimmed.len() > MAX_RUNBOOK_ID_LEN {
        return Err(format!("{}: {} exceeds maximum length {}", RUNBOOK_ERR_BOUNDS_EXCEEDED, field_name, MAX_RUNBOOK_ID_LEN));
    }
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') {
        return Err(format!("{}: {} contains invalid characters (allowed: alphanumeric, '_', '-', '.')", RUNBOOK_ERR_INVALID_ID, field_name));
    }
    Ok(())
}

pub fn validate_title(title: &str, field_name: &str) -> Result<(), String> {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return Err(format!("{}: {} cannot be empty", RUNBOOK_ERR_INVALID_TITLE, field_name));
    }
    if trimmed.len() > MAX_RUNBOOK_TITLE_LEN {
        return Err(format!("{}: {} exceeds maximum length {}", RUNBOOK_ERR_BOUNDS_EXCEEDED, field_name, MAX_RUNBOOK_TITLE_LEN));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(format!("{}: {} contains forbidden control characters", RUNBOOK_ERR_CONTROL_CHARS, field_name));
    }
    Ok(())
}

pub fn validate_text_length(text: &str, max_len: usize, field_name: &str) -> Result<(), String> {
    if text.len() > max_len {
        return Err(format!("{}: {} exceeds maximum length {}", RUNBOOK_ERR_BOUNDS_EXCEEDED, field_name, max_len));
    }
    if text.chars().any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t') {
        return Err(format!("{}: {} contains forbidden control characters", RUNBOOK_ERR_CONTROL_CHARS, field_name));
    }
    Ok(())
}
