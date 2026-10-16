//! Incident Response Runbooks Documentation Subsystem (IRDOC1..IRDOC5).
//!
//! Provides an offline, self-contained reference repository and search index for
//! Incident Response Runbooks, playbook schemas, execution state progression,
//! RustSec scanning tools, security policies, and observability metrics.

use serde::{Deserialize, Serialize};

pub const MAX_RUNBOOK_DOC_QUERY_LEN: usize = 128;
pub const MAX_RUNBOOK_DOC_SEARCH_RESULTS: usize = 10;
pub const MAX_RUNBOOK_DOC_SNIPPET_LEN: usize = 200;
pub const MAX_RUNBOOK_DOC_TOPICS_COUNT: usize = 256;
pub const MAX_RUNBOOK_DOC_TEXT_LEN: usize = 8192;

pub const IRDOC_ERR_NOT_FOUND: &str = "IRDOC_ERR_NOT_FOUND";
pub const IRDOC_ERR_QUERY_BOUNDS: &str = "IRDOC_ERR_QUERY_BOUNDS";
pub const IRDOC_ERR_CAPACITY_EXCEEDED: &str = "IRDOC_ERR_CAPACITY_EXCEEDED";

/// Standard result envelope for Incident Response documentation operations (ADR-0035 §AF-2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookDocResultEnvelope<T> {
    pub ok: bool,
    pub data: Option<T>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub audit_row_required: bool,
}

impl<T> RunbookDocResultEnvelope<T> {
    pub fn success(data: T) -> Self {
        Self {
            ok: true,
            data: Some(data),
            error_code: None,
            error_message: None,
            audit_row_required: false,
        }
    }

    pub fn failure(code: &str, message: &str) -> Self {
        Self {
            ok: false,
            data: None,
            error_code: Some(code.to_string()),
            error_message: Some(message.to_string()),
            audit_row_required: true,
        }
    }
}

/// Identifies bidirectional override or zero-width formatting codepoints.
pub fn is_bidi_or_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Sanitizes search query string by stripping control characters, bidi overrides, and trimming.
pub fn sanitize_doc_query(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && !is_bidi_or_invisible(*c))
        .collect::<String>()
        .trim()
        .to_string()
}

/// Validates topic identifier against path traversal, control chars, boundary dots/hyphens, and delimiters.
pub fn validate_topic_id(id: &str) -> Result<(), &'static str> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(IRDOC_ERR_NOT_FOUND);
    }
    if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains('\0') {
        return Err(IRDOC_ERR_NOT_FOUND);
    }
    if trimmed.starts_with('.') || trimmed.ends_with('.') || trimmed.starts_with('-') || trimmed.ends_with('-') {
        return Err(IRDOC_ERR_NOT_FOUND);
    }
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') {
        return Err(IRDOC_ERR_NOT_FOUND);
    }
    Ok(())
}

/// Domain categories for Incident Response Runbooks documentation topics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookDocCategory {
    Architecture,
    DataModel,
    Lifecycle,
    SecurityTools,
    Policy,
    Observability,
    Recovery,
}

impl RunbookDocCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            RunbookDocCategory::Architecture => "architecture",
            RunbookDocCategory::DataModel => "datamodel",
            RunbookDocCategory::Lifecycle => "lifecycle",
            RunbookDocCategory::SecurityTools => "security_tools",
            RunbookDocCategory::Policy => "policy",
            RunbookDocCategory::Observability => "observability",
            RunbookDocCategory::Recovery => "recovery",
        }
    }
}

/// A section within a documentation topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookDocSection {
    pub title: String,
    pub content: String,
}

/// A comprehensive documentation topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookDocTopic {
    pub id: String,
    pub title: String,
    pub category: RunbookDocCategory,
    pub summary: String,
    pub sections: Vec<RunbookDocSection>,
    pub related_topics: Vec<String>,
}

impl RunbookDocTopic {
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
pub struct RunbookDocSearchResult {
    pub topic_id: String,
    pub title: String,
    pub category: RunbookDocCategory,
    pub score: usize,
    pub snippet: String,
}

/// In-memory repository containing Incident Response Runbooks reference topics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookDocRepository {
    pub topics: Vec<RunbookDocTopic>,
}

impl Default for RunbookDocRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl RunbookDocRepository {
    /// Creates a repository populated with canonical reference topics.
    pub fn new() -> Self {
        let mut repo = Self { topics: Vec::new() };
        repo.populate_canonical_topics();
        repo
    }

    /// Adds or updates a documentation topic in the repository with bounds checking.
    pub fn add_topic_safe(&mut self, topic: RunbookDocTopic) -> Result<(), &'static str> {
        if topic.summary.len() > MAX_RUNBOOK_DOC_TEXT_LEN {
            return Err(IRDOC_ERR_QUERY_BOUNDS);
        }
        for sec in &topic.sections {
            if sec.content.len() > MAX_RUNBOOK_DOC_TEXT_LEN || sec.title.len() > MAX_RUNBOOK_DOC_QUERY_LEN {
                return Err(IRDOC_ERR_QUERY_BOUNDS);
            }
        }
        if self.topics.len() >= MAX_RUNBOOK_DOC_TOPICS_COUNT && !self.topics.iter().any(|t| t.id == topic.id) {
            return Err(IRDOC_ERR_CAPACITY_EXCEEDED);
        }
        if let Some(idx) = self.topics.iter().position(|t| t.id == topic.id) {
            self.topics[idx] = topic;
        } else {
            self.topics.push(topic);
        }
        Ok(())
    }

    /// Adds or updates a documentation topic in the repository (unwrapping safe helper).
    pub fn add_topic(&mut self, topic: RunbookDocTopic) {
        let _ = self.add_topic_safe(topic);
    }

    /// Lists all registered documentation topics.
    pub fn list_topics(&self) -> &[RunbookDocTopic] {
        &self.topics
    }

    /// Filters documentation topics by category.
    pub fn list_by_category(&self, cat: RunbookDocCategory) -> Vec<&RunbookDocTopic> {
        self.topics.iter().filter(|t| t.category == cat).collect()
    }

    /// Retrieves a specific topic by topic ID.
    pub fn get_topic(&self, id: &str) -> Option<&RunbookDocTopic> {
        if validate_topic_id(id).is_err() {
            return None;
        }
        self.topics.iter().find(|t| t.id == id)
    }

    /// Safe envelope wrapper for retrieving a specific topic by topic ID.
    pub fn get_topic_safe(&self, id: &str) -> RunbookDocResultEnvelope<RunbookDocTopic> {
        if let Err(e) = validate_topic_id(id) {
            return RunbookDocResultEnvelope::failure(e, &format!("Invalid topic ID format: '{}'", id));
        }
        match self.topics.iter().find(|t| t.id == id) {
            Some(t) => RunbookDocResultEnvelope::success(t.clone()),
            None => RunbookDocResultEnvelope::failure(IRDOC_ERR_NOT_FOUND, &format!("Topic '{}' not found", id)),
        }
    }

    /// Searches documentation topics with ranked scoring.
    pub fn search(
        &self,
        query: &str,
        category: Option<RunbookDocCategory>,
    ) -> Result<Vec<RunbookDocSearchResult>, &'static str> {
        let sanitized = sanitize_doc_query(query);
        if sanitized.is_empty() {
            return Err(IRDOC_ERR_QUERY_BOUNDS);
        }
        if sanitized.len() > MAX_RUNBOOK_DOC_QUERY_LEN {
            return Err(IRDOC_ERR_QUERY_BOUNDS);
        }

        let tokens: Vec<String> = sanitized
            .split_whitespace()
            .map(|t| t.to_lowercase())
            .filter(|t| !t.is_empty())
            .collect();

        if tokens.is_empty() {
            return Err(IRDOC_ERR_QUERY_BOUNDS);
        }

        let mut results = Vec::new();

        for topic in &self.topics {
            if let Some(cat) = category {
                if topic.category != cat {
                    continue;
                }
            }

            let mut score = 0;
            let mut matched_snippet = String::new();

            let id_lower = topic.id.to_lowercase();
            let title_lower = topic.title.to_lowercase();
            let summary_lower = topic.summary.to_lowercase();

            for token in &tokens {
                if id_lower.contains(token) {
                    score += 15;
                    if matched_snippet.is_empty() {
                        matched_snippet = topic.summary.clone();
                    }
                }
                if title_lower.contains(token) {
                    score += 10;
                }
                if summary_lower.contains(token) {
                    score += 5;
                    if matched_snippet.is_empty() {
                        matched_snippet = topic.summary.clone();
                    }
                }
            }

            for sec in &topic.sections {
                let sec_title_lower = sec.title.to_lowercase();
                let sec_content_lower = sec.content.to_lowercase();
                for token in &tokens {
                    if sec_title_lower.contains(token) {
                        score += 3;
                    }
                    if sec_content_lower.contains(token) {
                        score += 1;
                        if matched_snippet.is_empty() {
                            matched_snippet = sec.content.clone();
                        }
                    }
                }
            }

            if score > 0 {
                let snippet = if matched_snippet.len() > MAX_RUNBOOK_DOC_SNIPPET_LEN {
                    format!("{}...", &matched_snippet[..MAX_RUNBOOK_DOC_SNIPPET_LEN])
                } else if matched_snippet.is_empty() {
                    topic.summary.clone()
                } else {
                    matched_snippet
                };

                results.push(RunbookDocSearchResult {
                    topic_id: topic.id.clone(),
                    title: topic.title.clone(),
                    category: topic.category,
                    score,
                    snippet,
                });
            }
        }

        results.sort_by(|a, b| b.score.cmp(&a.score));
        if results.len() > MAX_RUNBOOK_DOC_SEARCH_RESULTS {
            results.truncate(MAX_RUNBOOK_DOC_SEARCH_RESULTS);
        }

        Ok(results)
    }

    /// Safe envelope wrapper for searching documentation topics.
    pub fn search_safe(
        &self,
        query: &str,
        category: Option<RunbookDocCategory>,
    ) -> RunbookDocResultEnvelope<Vec<RunbookDocSearchResult>> {
        match self.search(query, category) {
            Ok(res) => RunbookDocResultEnvelope::success(res),
            Err(e) => RunbookDocResultEnvelope::failure(e, &format!("Doc search query error: {}", e)),
        }
    }

    /// Populates repository with the canonical set of topics.
    pub fn populate_canonical_topics(&mut self) {
        self.topics = vec![
            RunbookDocTopic {
                id: "runbook.arch.overview".to_string(),
                title: "Incident Response Runbooks Architecture".to_string(),
                category: RunbookDocCategory::Architecture,
                summary: "Architectural overview of the AIOS Incident Response Runbooks subsystem, aligned with NIST SP 800-61 Rev. 2 and CISA Playbooks.".to_string(),
                sections: vec![
                    RunbookDocSection {
                        title: "Core Architecture".to_string(),
                        content: "Dual-substrate implementation coordinating between RustSec scanning engines and FastMCP execution services.".to_string(),
                    },
                    RunbookDocSection {
                        title: "Security Governance".to_string(),
                        content: "Enforcing dual-gate dispatch: classifier rule-pack verification and PEP grant capability redemption before any destructive action.".to_string(),
                    },
                ],
                related_topics: vec!["runbook.datamodel.specs".to_string(), "runbook.policy.governance".to_string()],
            },
            RunbookDocTopic {
                id: "runbook.datamodel.specs".to_string(),
                title: "Incident Runbook Data Model Specifications".to_string(),
                category: RunbookDocCategory::DataModel,
                summary: "Specifications of IncidentRunbookSpec, step parameters, targets, and canonical baseline catalog.".to_string(),
                sections: vec![
                    RunbookDocSection {
                        title: "Runbook Schemas".to_string(),
                        content: "Canonical playbooks RB-IR-MALWARE-01 and RB-IR-ACCESS-01 covering containment, eradication, and recovery.".to_string(),
                    },
                ],
                related_topics: vec!["runbook.arch.overview".to_string(), "runbook.lifecycle.execution".to_string()],
            },
            RunbookDocTopic {
                id: "runbook.lifecycle.execution".to_string(),
                title: "Runbook Execution Lifecycle & Session Advancement".to_string(),
                category: RunbookDocCategory::Lifecycle,
                summary: "State machine rules governing session start, step progression, confirmation gates, and abort semantics.".to_string(),
                sections: vec![
                    RunbookDocSection {
                        title: "Session Transitions".to_string(),
                        content: "States progress from ACTIVE to COMPLETED, FAILED, or ABORTED with mandatory operator confirmation for high-risk steps.".to_string(),
                    },
                ],
                related_topics: vec!["runbook.policy.governance".to_string()],
            },
            RunbookDocTopic {
                id: "runbook.tools.scanning".to_string(),
                title: "RustSec Diagnostic Security Scanning Tools".to_string(),
                category: RunbookDocCategory::SecurityTools,
                summary: "Comprehensive guide to aiosh scan subcommands: net (port scan), files (pattern hunting), and web (path probing).".to_string(),
                sections: vec![
                    RunbookDocSection {
                        title: "Target Validation & Resource Clamping".to_string(),
                        content: "Strict whitelist target validation, path traversal prohibition, and bounded ports, depth, and file size limits.".to_string(),
                    },
                ],
                related_topics: vec!["runbook.arch.overview".to_string()],
            },
            RunbookDocTopic {
                id: "runbook.config.precedence".to_string(),
                title: "Runbook Configuration Precedence Ladder".to_string(),
                category: RunbookDocCategory::Architecture,
                summary: "4-level configuration hierarchy: Explicit CLI/MCP args > Environment Variables > Config File > Built-in Defaults.".to_string(),
                sections: vec![
                    RunbookDocSection {
                        title: "Configuration Resolution".to_string(),
                        content: "Resolves aiosh.runbook.toml with strict 64 KiB size caps and bounds validation.".to_string(),
                    },
                ],
                related_topics: vec!["runbook.policy.governance".to_string()],
            },
            RunbookDocTopic {
                id: "runbook.policy.governance".to_string(),
                title: "Runbook Security Policy & Gate Enforcement".to_string(),
                category: RunbookDocCategory::Policy,
                summary: "Policy evaluation regimes (Enforcing, Permissive, Disabled), confirmation token requirements, and ADR-0035 honest audit rows.".to_string(),
                sections: vec![
                    RunbookDocSection {
                        title: "Enforcement Regimes".to_string(),
                        content: "Fail-closed confirmation gating on containment actions; honest audit row required on permissive bypass.".to_string(),
                    },
                ],
                related_topics: vec!["runbook.observability.telemetry".to_string()],
            },
            RunbookDocTopic {
                id: "runbook.observability.telemetry".to_string(),
                title: "Incident Response Telemetry & Observability".to_string(),
                category: RunbookDocCategory::Observability,
                summary: "Real-time metrics aggregation, session utilization, healthy status monitoring, and ADR-0035 §AF-2 compliance.".to_string(),
                sections: vec![
                    RunbookDocSection {
                        title: "Observability Result Envelope".to_string(),
                        content: "Explicit error envelopes preventing silent failure and logging honest audit rows on capacity saturation.".to_string(),
                    },
                ],
                related_topics: vec!["runbook.policy.governance".to_string()],
            },
        ];
    }
}
