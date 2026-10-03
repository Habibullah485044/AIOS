//! Threat Model Maintenance Core Service (THREATSVC1..THREATSVC5).
//!
//! Provides the runtime threat model repository, scoped queries,
//! state transitions, risk assessments, and atomic persistence.

use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

use crate::canonical::utcnow_iso;
use crate::threat_model_data_model::*;

pub const DEFAULT_THREAT_MODEL_PATH: &str = "docs/threat_model.json";
pub const MAX_THREAT_ENTRIES_CAPACITY: usize = 512;
pub const MAX_THREAT_MODEL_STORE_SIZE: u64 = 1024 * 1024; // 1 MiB

pub const THREATSVC_ERR_NOT_FOUND: &str = "THREATSVC_ERR_NOT_FOUND";
pub const THREATSVC_ERR_CAPACITY_EXCEEDED: &str = "THREATSVC_ERR_CAPACITY_EXCEEDED";
pub const THREATSVC_ERR_FILE_SIZE: &str = "THREATSVC_ERR_FILE_SIZE";
pub const THREATSVC_ERR_PATH_TRAVERSAL: &str = "THREATSVC_ERR_PATH_TRAVERSAL";
pub const THREATSVC_ERR_IO: &str = "THREATSVC_ERR_IO";
pub const THREATSVC_ERR_PARSE: &str = "THREATSVC_ERR_PARSE";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatRiskAssessment {
    pub total_threats: usize,
    pub identified_count: usize,
    pub under_review_count: usize,
    pub mitigated_count: usize,
    pub accepted_count: usize,
    pub resolved_count: usize,
    pub critical_unmitigated_count: usize,
    pub overall_risk_score: u32,
    pub evaluated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatModelService {
    pub snapshot: ThreatModelSnapshot,
}

impl Default for ThreatModelService {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatModelService {
    pub fn new() -> Self {
        Self {
            snapshot: ThreatModelSnapshot::new("1.0.0"),
        }
    }

    pub fn with_canonical_threats() -> Self {
        let mut svc = Self::new();
        svc.populate_canonical_threats();
        svc
    }

    pub fn validate_path(path: &Path) -> Result<PathBuf, String> {
        let p_str = path.to_string_lossy();
        if p_str.contains("..")
            || p_str.starts_with("\\\\")
            || p_str.starts_with("//")
            || p_str.chars().any(|c| c.is_control())
        {
            return Err(format!("{}: Path contains forbidden sequences: {}", THREATSVC_ERR_PATH_TRAVERSAL, p_str));
        }
        Ok(path.to_path_buf())
    }

    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let valid_path = Self::validate_path(path)?;
        if !valid_path.exists() {
            return Err(format!("{}: Threat model file not found: {}", THREATSVC_ERR_IO, valid_path.display()));
        }

        let meta = fs::metadata(&valid_path)
            .map_err(|e| format!("{}: Failed reading metadata: {}", THREATSVC_ERR_IO, e))?;
        if meta.len() > MAX_THREAT_MODEL_STORE_SIZE {
            return Err(format!(
                "{}: File size {} exceeds maximum allowed {}",
                THREATSVC_ERR_FILE_SIZE,
                meta.len(),
                MAX_THREAT_MODEL_STORE_SIZE
            ));
        }

        let content = fs::read_to_string(&valid_path)
            .map_err(|e| format!("{}: Failed reading file: {}", THREATSVC_ERR_IO, e))?;
        let snapshot: ThreatModelSnapshot = serde_json::from_str(&content)
            .map_err(|e| format!("{}: Failed deserializing JSON: {}", THREATSVC_ERR_PARSE, e))?;

        Ok(Self { snapshot })
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), String> {
        let valid_path = Self::validate_path(path)?;
        let tmp_path = valid_path.with_extension("tmp.threat");

        let json_str = serde_json::to_string_pretty(&self.snapshot)
            .map_err(|e| format!("{}: Serialization error: {}", THREATSVC_ERR_IO, e))?;

        fs::write(&tmp_path, json_str)
            .map_err(|e| format!("{}: Failed writing tmp file: {}", THREATSVC_ERR_IO, e))?;
        fs::rename(&tmp_path, &valid_path)
            .map_err(|e| format!("{}: Failed atomic rename: {}", THREATSVC_ERR_IO, e))?;

        Ok(())
    }

    pub fn register_threat(&mut self, entry: ThreatEntry) -> Result<(), String> {
        if self.snapshot.threats.len() >= MAX_THREAT_ENTRIES_CAPACITY {
            return Err(format!(
                "{}: Threat catalog reached maximum capacity of {}",
                THREATSVC_ERR_CAPACITY_EXCEEDED,
                MAX_THREAT_ENTRIES_CAPACITY
            ));
        }
        self.snapshot.add_entry(entry)
    }

    pub fn get_threat(&self, id: &str) -> Option<&ThreatEntry> {
        self.snapshot.get_entry(id)
    }

    pub fn list_threats(&self) -> &[ThreatEntry] {
        &self.snapshot.threats
    }

    pub fn update_status(&mut self, id: &str, new_status: ThreatStatus) -> Result<(), String> {
        let entry = self.snapshot.get_entry_mut(id)
            .ok_or_else(|| format!("{}: Threat '{}' not found", THREATSVC_ERR_NOT_FOUND, id))?;
        entry.transition_to(new_status)
    }

    pub fn attach_mitigation(&mut self, id: &str, mitigation: &str) -> Result<(), String> {
        let entry = self.snapshot.get_entry_mut(id)
            .ok_or_else(|| format!("{}: Threat '{}' not found", THREATSVC_ERR_NOT_FOUND, id))?;
        entry.add_mitigation(mitigation)
    }

    pub fn assess_risk(&self) -> ThreatRiskAssessment {
        let mut identified = 0;
        let mut under_review = 0;
        let mut mitigated = 0;
        let mut accepted = 0;
        let mut resolved = 0;
        let mut critical_unmitigated = 0;
        let mut risk_score: u32 = 0;

        for t in &self.snapshot.threats {
            match t.status {
                ThreatStatus::Identified => {
                    identified += 1;
                    risk_score += match t.severity {
                        ThreatSeverity::Critical => {
                            critical_unmitigated += 1;
                            10
                        }
                        ThreatSeverity::High => 5,
                        ThreatSeverity::Medium => 2,
                        ThreatSeverity::Low => 1,
                    };
                }
                ThreatStatus::UnderReview => {
                    under_review += 1;
                    risk_score += match t.severity {
                        ThreatSeverity::Critical => {
                            critical_unmitigated += 1;
                            8
                        }
                        ThreatSeverity::High => 4,
                        ThreatSeverity::Medium => 2,
                        ThreatSeverity::Low => 1,
                    };
                }
                ThreatStatus::Mitigated => {
                    mitigated += 1;
                }
                ThreatStatus::Accepted => {
                    accepted += 1;
                    risk_score += match t.severity {
                        ThreatSeverity::Critical => 3,
                        ThreatSeverity::High => 2,
                        ThreatSeverity::Medium => 1,
                        ThreatSeverity::Low => 0,
                    };
                }
                ThreatStatus::Resolved => {
                    resolved += 1;
                }
            }
        }

        ThreatRiskAssessment {
            total_threats: self.snapshot.threats.len(),
            identified_count: identified,
            under_review_count: under_review,
            mitigated_count: mitigated,
            accepted_count: accepted,
            resolved_count: resolved,
            critical_unmitigated_count: critical_unmitigated,
            overall_risk_score: risk_score,
            evaluated_at: utcnow_iso(),
        }
    }

    fn populate_canonical_threats(&mut self) {
        let threats = vec![
            (
                "THREAT-SPOOF-01",
                "Unauthenticated Agent Token Impersonation",
                "Adversary presents forged grant token to impersonate privileged actor",
                ThreatCategory::Spoofing,
                ThreatSeverity::Critical,
                "pep_fabric",
                vec!["CWE-287".into()],
                vec!["Cryptographic HMAC token verification in PEP authorization gate".into()],
            ),
            (
                "THREAT-TAMP-01",
                "Task Ledger State Tampering",
                "Concurrent writer manipulates TASK_STATE pointer outside mechanical no-skip order",
                ThreatCategory::Tampering,
                ThreatSeverity::High,
                "ledger_control",
                vec!["CWE-367".into()],
                vec!["Advisory file locking (LockFileEx/flock) and strict next_task validation".into()],
            ),
            (
                "THREAT-REPU-01",
                "Audit Event Dropping & Disavowal",
                "Rogue operator disables audit ring or floods memory ring to overwrite security traces",
                ThreatCategory::Repudiation,
                ThreatSeverity::High,
                "audit_ring",
                vec!["CWE-778".into()],
                vec!["Append-only jsonl fallback and tamper-evident audit record sequence counters".into()],
            ),
            (
                "THREAT-INFO-01",
                "Plaintext Vault Credential Leakage",
                "Secret plaintext disclosed in observability reports, telemetry, or error messages",
                ThreatCategory::InformationDisclosure,
                ThreatSeverity::Critical,
                "secrets_vault",
                vec!["CWE-200".into(), "CWE-312".into()],
                vec!["Zero-Disclosure Invariant: masked serialization and scrubbed error messages".into()],
            ),
            (
                "THREAT-DOS-01",
                "Resource Exhaustion via Unbounded Subprocess Spawning",
                "Malicious agent spawns excessive worker loops exhausting CPU and OS handles",
                ThreatCategory::DenialOfService,
                ThreatSeverity::Medium,
                "sandbox_runtime",
                vec!["CWE-400".into()],
                vec!["Cgroup/JobObject resource quotas and process count limits".into()],
            ),
            (
                "THREAT-EOP-01",
                "Userspace Escalation to System Kernel Privilege",
                "Agent issues syscall to elevate from Guest/User to SystemKernel tier",
                ThreatCategory::ElevationOfPrivilege,
                ThreatSeverity::Critical,
                "privilege_manager",
                vec!["CWE-250".into()],
                vec!["PRIVESC2 Kernel Tier Immutability rule refusing all userspace transitions".into()],
            ),
            (
                "THREAT-SUPPLY-01",
                "Compromised Base Container Image",
                "Imported container base image contains trojaned root certificate or backdoor",
                ThreatCategory::SupplyChainRisk,
                ThreatSeverity::High,
                "base_image",
                vec!["CWE-829".into()],
                vec!["SHA-256 digest validation and verified signature manifest enforcement".into()],
            ),
        ];

        for (id, title, desc, cat, sev, comp, cwes, mits) in threats {
            if let Ok(mut entry) = ThreatEntry::new(id, title, desc, cat, sev, comp, cwes, mits) {
                let _ = entry.transition_to(ThreatStatus::Mitigated);
                let _ = self.snapshot.add_entry(entry);
            }
        }
    }
}
