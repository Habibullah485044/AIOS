//! Threat Model Documentation Subsystem (THREATDOC1..THREATDOC5).
//!
//! Provides an offline, self-contained reference repository and search index for
//! Threat Model Maintenance, STRIDE taxonomy, lifecycle state rules,
//! security policy gates, telemetry schemas, and recovery protocols.

use serde::{Deserialize, Serialize};

pub const MAX_THREAT_DOC_QUERY_LEN: usize = 128;
pub const MAX_THREAT_DOC_SEARCH_RESULTS: usize = 10;
pub const MAX_THREAT_DOC_SNIPPET_LEN: usize = 200;

pub const THREATDOC_ERR_NOT_FOUND: &str = "THREATDOC_ERR_NOT_FOUND";
pub const THREATDOC_ERR_QUERY_BOUNDS: &str = "THREATDOC_ERR_QUERY_BOUNDS";

/// Domain categories for Threat Model documentation topics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatDocCategory {
    Architecture,
    Lifecycle,
    Service,
    Policy,
    Observability,
    Recovery,
}

impl ThreatDocCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatDocCategory::Architecture => "architecture",
            ThreatDocCategory::Lifecycle => "lifecycle",
            ThreatDocCategory::Service => "service",
            ThreatDocCategory::Policy => "policy",
            ThreatDocCategory::Observability => "observability",
            ThreatDocCategory::Recovery => "recovery",
        }
    }
}

/// A section within a documentation topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatDocSection {
    pub title: String,
    pub content: String,
}

/// A comprehensive documentation topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatDocTopic {
    pub id: String,
    pub title: String,
    pub category: ThreatDocCategory,
    pub summary: String,
    pub sections: Vec<ThreatDocSection>,
    pub related_topics: Vec<String>,
}

impl ThreatDocTopic {
    /// Formats topic into human-readable Markdown.
    pub fn to_markdown(&self) -> String {
        let mut md = format!(
            "# {}\n\n**Category**: `{}`\n**ID**: `{}`\n\n{}\n\n",
            self.title,
            self.category.as_str(),
            self.id,
            self.summary
        );
        for sec in &self.sections {
            md.push_str(&format!("## {}\n\n{}\n\n", sec.title, sec.content));
        }
        if !self.related_topics.is_empty() {
            md.push_str("### Related Topics\n\n");
            for rel in &self.related_topics {
                md.push_str(&format!("- `{}`\n", rel));
            }
        }
        md
    }
}

/// A search hit with scoring and text snippet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatDocSearchResult {
    pub topic_id: String,
    pub title: String,
    pub category: ThreatDocCategory,
    pub score: usize,
    pub snippet: String,
}

/// In-memory repository containing Threat Model reference topics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatDocRepository {
    pub topics: Vec<ThreatDocTopic>,
}

impl Default for ThreatDocRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatDocRepository {
    /// Creates a repository populated with canonical reference topics.
    pub fn new() -> Self {
        let mut repo = Self { topics: Vec::new() };
        repo.populate_canonical_topics();
        repo
    }

    /// Lists all registered documentation topics.
    pub fn list_topics(&self) -> &[ThreatDocTopic] {
        &self.topics
    }

    /// Filters documentation topics by category.
    pub fn list_by_category(&self, cat: ThreatDocCategory) -> Vec<&ThreatDocTopic> {
        self.topics.iter().filter(|t| t.category == cat).collect()
    }

    /// Looks up a documentation topic by ID with input sanitization.
    pub fn get_topic(&self, id: &str) -> Option<&ThreatDocTopic> {
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

    /// Renders a topic to Markdown or returns an error if not found.
    pub fn render_markdown(&self, id: &str) -> Result<String, String> {
        let topic = self.get_topic(id)
            .ok_or_else(|| format!("{}: Topic '{}' not found", THREATDOC_ERR_NOT_FOUND, id))?;
        Ok(topic.to_markdown())
    }

    /// Searches documentation topics by query keywords with relevance scoring.
    pub fn search(&self, query: &str) -> Result<Vec<ThreatDocSearchResult>, String> {
        let q = query.trim();
        if q.is_empty() {
            return Err(format!("{}: Query cannot be empty", THREATDOC_ERR_QUERY_BOUNDS));
        }
        if q.chars().any(|c| c.is_control()) {
            return Err(format!("{}: Query contains control characters", THREATDOC_ERR_QUERY_BOUNDS));
        }
        if q.len() > MAX_THREAT_DOC_QUERY_LEN {
            return Err(format!(
                "{}: Query length {} exceeds maximum allowed {}",
                THREATDOC_ERR_QUERY_BOUNDS,
                q.len(),
                MAX_THREAT_DOC_QUERY_LEN
            ));
        }

        let query_tokens: Vec<String> = q
            .to_lowercase()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();

        if query_tokens.is_empty() {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();

        for topic in &self.topics {
            let mut score = 0;
            let mut best_snippet = topic.summary.clone();

            for token in &query_tokens {
                if topic.id.to_lowercase().contains(token) {
                    score += 50;
                }
                if topic.title.to_lowercase().contains(token) {
                    score += 25;
                }
                if topic.summary.to_lowercase().contains(token) {
                    score += 15;
                }
                for section in &topic.sections {
                    if section.title.to_lowercase().contains(token) {
                        score += 5;
                    }
                    if section.content.to_lowercase().contains(token) {
                        score += 2;
                        if best_snippet == topic.summary {
                            best_snippet = extract_snippet(&section.content, token);
                        }
                    }
                }
            }

            if score > 0 {
                results.push(ThreatDocSearchResult {
                    topic_id: topic.id.clone(),
                    title: topic.title.clone(),
                    category: topic.category,
                    score,
                    snippet: truncate_snippet(&best_snippet),
                });
            }
        }

        results.sort_by(|a, b| b.score.cmp(&a.score));
        if results.len() > MAX_THREAT_DOC_SEARCH_RESULTS {
            results.truncate(MAX_THREAT_DOC_SEARCH_RESULTS);
        }

        Ok(results)
    }

    fn populate_canonical_topics(&mut self) {
        self.topics = vec![
            ThreatDocTopic {
                id: "threat.arch.stride".into(),
                title: "STRIDE Threat Modeling Architecture".into(),
                category: ThreatDocCategory::Architecture,
                summary: "Core architecture of the AIOS STRIDE threat modeling framework and security boundaries.".into(),
                sections: vec![
                    ThreatDocSection {
                        title: "STRIDE Classification Matrix".into(),
                        content: "Threats are categorized under Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.".into(),
                    },
                    ThreatDocSection {
                        title: "Security Invariants".into(),
                        content: "Invariants THREAT1 through THREAT8 govern baseline initialization, capacity bounds, and fail-closed behavior.".into(),
                    },
                ],
                related_topics: vec!["threat.lifecycle.states".into(), "threat.policy.gates".into()],
            },
            ThreatDocTopic {
                id: "threat.lifecycle.states".into(),
                title: "Threat Lifecycle State Machine".into(),
                category: ThreatDocCategory::Lifecycle,
                summary: "Formal state transitions from Identified to Resolved with verification criteria.".into(),
                sections: vec![
                    ThreatDocSection {
                        title: "Lifecycle States".into(),
                        content: "Valid states: Identified, UnderReview, Mitigated, Accepted, and Resolved.".into(),
                    },
                    ThreatDocSection {
                        title: "Transition Invariants".into(),
                        content: "Transition to Mitigated requires at least one mitigation recorded. Critical threats cannot be Accepted or Resolved without mitigations.".into(),
                    },
                ],
                related_topics: vec!["threat.arch.stride".into(), "threat.service.api".into()],
            },
            ThreatDocTopic {
                id: "threat.service.api".into(),
                title: "Threat Model Service API & Persistence".into(),
                category: ThreatDocCategory::Service,
                summary: "In-memory service operations, monotonic risk scoring, and atomic file persistence.".into(),
                sections: vec![
                    ThreatDocSection {
                        title: "Service Methods".into(),
                        content: "ThreatModelService provides register_threat, update_status, attach_mitigation, and assess_risk.".into(),
                    },
                    ThreatDocSection {
                        title: "Atomic File Persistence".into(),
                        content: "Saves use atomic temporary files with PID and timestamp to prevent torn writes during power loss.".into(),
                    },
                ],
                related_topics: vec!["threat.lifecycle.states".into(), "threat.recovery.backup".into()],
            },
            ThreatDocTopic {
                id: "threat.policy.gates".into(),
                title: "Threat Model Security Policy Gates".into(),
                category: ThreatDocCategory::Policy,
                summary: "Declarative policy governance, modes (Enforcing/Permissive), and fail-closed gates.".into(),
                sections: vec![
                    ThreatDocSection {
                        title: "Policy Modes".into(),
                        content: "Enforcing mode rejects non-compliant actions. Permissive emits auditable security warnings. Disabled bypasses evaluation.".into(),
                    },
                    ThreatDocSection {
                        title: "Mandatory Invariants".into(),
                        content: "THREATPOL1..THREATPOL7 enforce CWE requirements, category blocks, and density bounds.".into(),
                    },
                ],
                related_topics: vec!["threat.arch.stride".into(), "threat.observability.metrics".into()],
            },
            ThreatDocTopic {
                id: "threat.observability.metrics".into(),
                title: "Threat Model Observability & Telemetry".into(),
                category: ThreatDocCategory::Observability,
                summary: "Real-time metrics, STRIDE distributions, and audit trail correlation without secret disclosure.".into(),
                sections: vec![
                    ThreatDocSection {
                        title: "Metrics Report Schema".into(),
                        content: "ThreatModelObservabilityReport provides distribution maps, critical counts, risk score, and policy state.".into(),
                    },
                    ThreatDocSection {
                        title: "Audit Correlation".into(),
                        content: "Integrates with AuditRing SQLite WAL trail to count recent threat operations.".into(),
                    },
                ],
                related_topics: vec!["threat.policy.gates".into(), "threat.service.api".into()],
            },
            ThreatDocTopic {
                id: "threat.recovery.backup".into(),
                title: "Threat Catalog Disaster Recovery & Backup".into(),
                category: ThreatDocCategory::Recovery,
                summary: "Procedures for catalog state recovery, corruption detection, and emergency rollback.".into(),
                sections: vec![
                    ThreatDocSection {
                        title: "Corruption Handling".into(),
                        content: "Malformed JSON files are detected on load with THREATSVC_ERR_PARSE, enabling fallback to backup files.".into(),
                    },
                    ThreatDocSection {
                        title: "Backup Strategy".into(),
                        content: "Point-in-time snapshots and atomic renames preserve data integrity across sudden terminations.".into(),
                    },
                ],
                related_topics: vec!["threat.service.api".into()],
            },
        ];
    }
}

fn extract_snippet(content: &str, token: &str) -> String {
    if let Some(pos) = content.to_lowercase().find(token) {
        let start = pos.saturating_sub(40);
        let end = (pos + token.len() + 100).min(content.len());
        content[start..end].trim().to_string()
    } else {
        content.chars().take(MAX_THREAT_DOC_SNIPPET_LEN).collect()
    }
}

fn truncate_snippet(snippet: &str) -> String {
    if snippet.len() > MAX_THREAT_DOC_SNIPPET_LEN {
        format!("{}...", &snippet[..MAX_THREAT_DOC_SNIPPET_LEN])
    } else {
        snippet.to_string()
    }
}
