//! Secrets Handling Documentation Subsystem (SECDOC1..SECDOC5).
//!
//! Provides an offline, self-contained reference repository and search index for
//! Secrets Handling, vault operations, policy rules, and recovery workflows.

use serde::{Deserialize, Serialize};

pub const MAX_SECRET_DOC_QUERY_LEN: usize = 128;
pub const MAX_SECRET_DOC_SEARCH_RESULTS: usize = 10;
pub const MAX_SECRET_DOC_SNIPPET_LEN: usize = 200;

pub const SECDOC_ERR_NOT_FOUND: &str = "SECDOC_ERR_NOT_FOUND";
pub const SECDOC_ERR_QUERY_BOUNDS: &str = "SECDOC_ERR_QUERY_BOUNDS";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretDocCategory {
    Architecture,
    Lifecycle,
    Policy,
    Observability,
    Security,
    Recovery,
}

impl SecretDocCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretDocCategory::Architecture => "architecture",
            SecretDocCategory::Lifecycle => "lifecycle",
            SecretDocCategory::Policy => "policy",
            SecretDocCategory::Observability => "observability",
            SecretDocCategory::Security => "security",
            SecretDocCategory::Recovery => "recovery",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretDocSection {
    pub title: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretDocTopic {
    pub id: String,
    pub title: String,
    pub category: SecretDocCategory,
    pub summary: String,
    pub sections: Vec<SecretDocSection>,
    pub related_topics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretDocSearchResult {
    pub topic_id: String,
    pub title: String,
    pub category: SecretDocCategory,
    pub score: usize,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretDocRepository {
    pub topics: Vec<SecretDocTopic>,
}

impl Default for SecretDocRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDocRepository {
    pub fn new() -> Self {
        let mut repo = Self { topics: Vec::new() };
        repo.populate_canonical_topics();
        repo
    }

    pub fn list_topics(&self) -> &[SecretDocTopic] {
        &self.topics
    }

    pub fn get_topic(&self, id: &str) -> Option<&SecretDocTopic> {
        let trimmed = id.trim();
        if trimmed.is_empty()
            || trimmed.len() > 64
            || trimmed.chars().any(|c| c.is_control() || c == '<' || c == '>' || c == '/' || c == '\\')
            || trimmed.contains("..")
        {
            return None;
        }
        self.topics.iter().find(|t| t.id == trimmed)
    }

    pub fn search(&self, query: &str) -> Result<Vec<SecretDocSearchResult>, String> {
        let q = query.trim();
        if q.is_empty() {
            return Err(format!("{}: Search query must not be empty", SECDOC_ERR_QUERY_BOUNDS));
        }
        if q.chars().any(|c| c.is_control() || c == '<' || c == '>') {
            return Err(format!("{}: Search query contains forbidden control or markup characters", SECDOC_ERR_QUERY_BOUNDS));
        }
        if q.len() > MAX_SECRET_DOC_QUERY_LEN {
            return Err(format!(
                "{}: Search query length {} exceeds max {}",
                SECDOC_ERR_QUERY_BOUNDS,
                q.len(),
                MAX_SECRET_DOC_QUERY_LEN
            ));
        }

        let q_lower = q.to_ascii_lowercase();
        let tokens: Vec<&str> = q_lower.split_whitespace().collect();

        let mut results = Vec::new();

        for topic in &self.topics {
            let mut score = 0;
            let mut matched_snippet = String::new();

            for token in &tokens {
                if topic.id.to_ascii_lowercase().contains(token) {
                    score += 50;
                }

                if topic.title.to_ascii_lowercase().contains(token) {
                    score += 25;
                }

                if topic.summary.to_ascii_lowercase().contains(token) {
                    score += 15;
                    if matched_snippet.is_empty() {
                        matched_snippet = topic.summary.clone();
                    }
                }

                for sec in &topic.sections {
                    if sec.title.to_ascii_lowercase().contains(token) {
                        score += 5;
                    }
                    if sec.content.to_ascii_lowercase().contains(token) {
                        score += 2;
                        if matched_snippet.is_empty() {
                            matched_snippet = sec.content.chars().take(MAX_SECRET_DOC_SNIPPET_LEN).collect();
                        }
                    }
                }
            }

            if score > 0 {
                if matched_snippet.is_empty() {
                    matched_snippet = topic.summary.chars().take(MAX_SECRET_DOC_SNIPPET_LEN).collect();
                }
                results.push(SecretDocSearchResult {
                    topic_id: topic.id.clone(),
                    title: topic.title.clone(),
                    category: topic.category,
                    score,
                    snippet: matched_snippet,
                });
            }
        }

        results.sort_by(|a, b| b.score.cmp(&a.score));
        results.truncate(MAX_SECRET_DOC_SEARCH_RESULTS);
        Ok(results)
    }

    pub fn render_markdown(&self, topic_id: &str) -> Result<String, String> {
        let topic = self
            .get_topic(topic_id)
            .ok_or_else(|| format!("{}: topic '{}' not found", SECDOC_ERR_NOT_FOUND, topic_id))?;

        let mut md = String::new();
        md.push_str(&format!("# {}\n\n", topic.title));
        md.push_str(&format!("**Category:** `{}`  \n", topic.category.as_str()));
        md.push_str(&format!("## Summary\n{}\n\n", topic.summary));

        for sec in &topic.sections {
            md.push_str(&format!("## {}\n{}\n\n", sec.title, sec.content));
        }

        if !topic.related_topics.is_empty() {
            md.push_str(&format!("**Related Topics:** {}\n", topic.related_topics.join(", ")));
        }

        Ok(md)
    }

    fn populate_canonical_topics(&mut self) {
        self.topics.push(SecretDocTopic {
            id: "secrets-overview".into(),
            title: "Secrets Vault Architecture & Zero-Disclosure Model".into(),
            category: SecretDocCategory::Architecture,
            summary: "Overview of the AIOS runtime secrets vault, scoped storage tiers, and zero-disclosure rules.".into(),
            sections: vec![
                SecretDocSection {
                    title: "Zero-Disclosure Model".into(),
                    content: "Plaintext secrets are never serialized into telemetry, error responses, or logs. Vault payloads are kept in isolated structures and wiped on revocation.".into(),
                },
                SecretDocSection {
                    title: "Scope Hierarchy".into(),
                    content: "Secrets are compartmentalized into Global, Actor, Session, and Environment scopes. Access requires matching caller privilege or explicit scope delegation.".into(),
                },
            ],
            related_topics: vec!["secrets-lifecycle".into(), "secrets-security".into()],
        });

        self.topics.push(SecretDocTopic {
            id: "secrets-lifecycle".into(),
            title: "Secret Registration, Retrieval, Rotation & Revocation".into(),
            category: SecretDocCategory::Lifecycle,
            summary: "Lifecycle workflows governing secret creation, reading, rotating, and irreversible revocation.".into(),
            sections: vec![
                SecretDocSection {
                    title: "Registration & Retrieval".into(),
                    content: "Secrets are registered via store_secret() with explicit SecretKind and SecretScope. Retrieval enforces scope checks and returns masked representations unless --expose is granted.".into(),
                },
                SecretDocSection {
                    title: "Rotation & Revocation".into(),
                    content: "Rotation updates secret bytes while incrementing version counters. Revocation wipes the payload and marks the entry permanently inaccessible.".into(),
                },
            ],
            related_topics: vec!["secrets-overview".into(), "secrets-policy".into()],
        });

        self.topics.push(SecretDocTopic {
            id: "secrets-policy".into(),
            title: "Declarative Security Policy Enforcement".into(),
            category: SecretDocCategory::Policy,
            summary: "Rule-based security governance with tri-state policy modes, payload bounds, and prohibited kinds.".into(),
            sections: vec![
                SecretDocSection {
                    title: "Policy Modes".into(),
                    content: "Enforcing mode rejects violations fail-closed. Permissive mode records auditable warnings. Disabled mode permits requests unconditionally for testing.".into(),
                },
                SecretDocSection {
                    title: "Governance Rules".into(),
                    content: "Policies enforce max_payload_bytes (default 64 KiB), disallow_global_secrets, and blacklist prohibited kinds such as raw PrivateKey in non-isolated scopes.".into(),
                },
            ],
            related_topics: vec!["secrets-lifecycle".into(), "secrets-security".into()],
        });

        self.topics.push(SecretDocTopic {
            id: "secrets-observability".into(),
            title: "Telemetry, Metrics & Health Monitoring".into(),
            category: SecretDocCategory::Observability,
            summary: "Point-in-time metrics aggregation, scope and kind distributions, and zero-disclosure health status.".into(),
            sections: vec![
                SecretDocSection {
                    title: "Telemetry Invariants".into(),
                    content: "Telemetry collects category counts, active vs expired secret counts, and audit event counts. Distribution maps are capped at 128 entries to prevent memory exhaustion.".into(),
                },
            ],
            related_topics: vec!["secrets-overview".into(), "secrets-policy".into()],
        });

        self.topics.push(SecretDocTopic {
            id: "secrets-security".into(),
            title: "Threat Model & Security Hardening".into(),
            category: SecretDocCategory::Security,
            summary: "Mitigations against path traversal, memory exhaustion, injection, and unauthorized secret exposure.".into(),
            sections: vec![
                SecretDocSection {
                    title: "Path Traversal Mitigation".into(),
                    content: "All file operations validate paths rejecting '..' and control characters. Symlinks targeting vault files are refused fail-closed.".into(),
                },
            ],
            related_topics: vec!["secrets-overview".into(), "secrets-recovery".into()],
        });

        self.topics.push(SecretDocTopic {
            id: "secrets-recovery".into(),
            title: "Vault Validation, Integrity Check & Atomic Persistence".into(),
            category: SecretDocCategory::Recovery,
            summary: "Integrity validation, atomic save mechanics, and corrupted file recovery strategies.".into(),
            sections: vec![
                SecretDocSection {
                    title: "Atomic Persistence".into(),
                    content: "Vault states are written to temporary files and atomically renamed, preventing half-written files on unexpected termination.".into(),
                },
            ],
            related_topics: vec!["secrets-security".into()],
        });
    }
}
