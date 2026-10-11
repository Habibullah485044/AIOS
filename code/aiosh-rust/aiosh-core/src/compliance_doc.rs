//! Compliance Mapping Documentation Subsystem (COMPLYDOC1..COMPLYDOC5).
//!
//! Provides an offline, self-contained reference repository and search index for
//! Compliance Mapping, regulatory frameworks taxonomy, lifecycle state rules,
//! security policy gates, telemetry schemas, and recovery protocols.

use serde::{Deserialize, Serialize};

pub const MAX_COMPLIANCE_DOC_QUERY_LEN: usize = 128;
pub const MAX_COMPLIANCE_DOC_SEARCH_RESULTS: usize = 10;
pub const MAX_COMPLIANCE_DOC_SNIPPET_LEN: usize = 200;

pub const COMPLYDOC_ERR_NOT_FOUND: &str = "COMPLYDOC_ERR_NOT_FOUND";
pub const COMPLYDOC_ERR_QUERY_BOUNDS: &str = "COMPLYDOC_ERR_QUERY_BOUNDS";

/// Sanitizes search query string by stripping control characters and trimming.
pub fn sanitize_doc_query(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string()
}

/// Validates topic identifier against path traversal, control chars, and delimiters.
pub fn validate_topic_id(id: &str) -> Result<(), &'static str> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(COMPLYDOC_ERR_NOT_FOUND);
    }
    if trimmed.contains("..") || trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains('\0') {
        return Err(COMPLYDOC_ERR_NOT_FOUND);
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(COMPLYDOC_ERR_NOT_FOUND);
    }
    Ok(())
}

/// Domain categories for Compliance Mapping documentation topics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceDocCategory {
    Architecture,
    Frameworks,
    Lifecycle,
    Service,
    Policy,
    Observability,
    Recovery,
}

impl ComplianceDocCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ComplianceDocCategory::Architecture => "architecture",
            ComplianceDocCategory::Frameworks => "frameworks",
            ComplianceDocCategory::Lifecycle => "lifecycle",
            ComplianceDocCategory::Service => "service",
            ComplianceDocCategory::Policy => "policy",
            ComplianceDocCategory::Observability => "observability",
            ComplianceDocCategory::Recovery => "recovery",
        }
    }
}

/// A section within a documentation topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceDocSection {
    pub title: String,
    pub content: String,
}

/// A comprehensive documentation topic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceDocTopic {
    pub id: String,
    pub title: String,
    pub category: ComplianceDocCategory,
    pub summary: String,
    pub sections: Vec<ComplianceDocSection>,
    pub related_topics: Vec<String>,
}

impl ComplianceDocTopic {
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
pub struct ComplianceDocSearchResult {
    pub topic_id: String,
    pub title: String,
    pub category: ComplianceDocCategory,
    pub score: usize,
    pub snippet: String,
}

/// In-memory repository containing Compliance Mapping reference topics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceDocRepository {
    pub topics: Vec<ComplianceDocTopic>,
}

impl Default for ComplianceDocRepository {
    fn default() -> Self {
        Self::with_canonical_topics()
    }
}

impl ComplianceDocRepository {
    /// Creates an empty repository.
    pub fn new() -> Self {
        Self { topics: Vec::new() }
    }

    /// Creates repository populated with canonical compliance topics.
    pub fn with_canonical_topics() -> Self {
        let mut repo = Self::new();
        repo.populate_canonical_topics();
        repo
    }

    /// Populates repository with canonical reference topics.
    pub fn populate_canonical_topics(&mut self) {
        self.topics = vec![
            ComplianceDocTopic {
                id: "compliance.arch.overview".to_string(),
                title: "Compliance Mapping Architecture & Target Bindings".to_string(),
                category: ComplianceDocCategory::Architecture,
                summary: "Comprehensive architecture of AIOS compliance mapping connecting regulatory controls to concrete execution substrates.".to_string(),
                sections: vec![
                    ComplianceDocSection {
                        title: "Substrate Target Types".to_string(),
                        content: "Supported targets include PEP gates, audit rings, sandbox profiles, capability grants, and system update verifiers.".to_string(),
                    },
                    ComplianceDocSection {
                        title: "Data Model".to_string(),
                        content: "Compliance mappings bind unique mapping IDs, control IDs, regulatory frameworks, substrate targets, lifecycle statuses, and MITRE threat IDs.".to_string(),
                    },
                ],
                related_topics: vec![
                    "compliance.frameworks.taxonomy".to_string(),
                    "compliance.lifecycle.states".to_string(),
                ],
            },
            ComplianceDocTopic {
                id: "compliance.frameworks.taxonomy".to_string(),
                title: "Supported Regulatory Frameworks Taxonomy".to_string(),
                category: ComplianceDocCategory::Frameworks,
                summary: "Taxonomy of supported security and compliance frameworks in AIOS.".to_string(),
                sections: vec![
                    ComplianceDocSection {
                        title: "NIST SP 800-53 Rev 5".to_string(),
                        content: "Federal information system security controls catalog covering AC, AU, SI, and SC families.".to_string(),
                    },
                    ComplianceDocSection {
                        title: "ISO/IEC 27001:2022".to_string(),
                        content: "Information security management systems controls in Annex A.".to_string(),
                    },
                    ComplianceDocSection {
                        title: "SOC 2 Type II".to_string(),
                        content: "Trust Services Criteria covering security, availability, and confidentiality.".to_string(),
                    },
                    ComplianceDocSection {
                        title: "CIS Controls v8".to_string(),
                        content: "Prioritized set of 18 critical security actions.".to_string(),
                    },
                ],
                related_topics: vec![
                    "compliance.arch.overview".to_string(),
                    "compliance.policy.gates".to_string(),
                ],
            },
            ComplianceDocTopic {
                id: "compliance.lifecycle.states".to_string(),
                title: "Compliance Lifecycle States & Transition Rules".to_string(),
                category: ComplianceDocCategory::Lifecycle,
                summary: "Formal state machine rules governing mapping status transitions from non-compliant to verified compliant.".to_string(),
                sections: vec![
                    ComplianceDocSection {
                        title: "Status States".to_string(),
                        content: "Valid lifecycle statuses are 'non_compliant', 'partially_compliant', 'compliant', and 'not_applicable'.".to_string(),
                    },
                    ComplianceDocSection {
                        title: "Transition Invariants".to_string(),
                        content: "Transitions require valid cryptographic rationale and maintain monotonically non-decreasing evidence validation.".to_string(),
                    },
                ],
                related_topics: vec![
                    "compliance.service.api".to_string(),
                    "compliance.policy.gates".to_string(),
                ],
            },
            ComplianceDocTopic {
                id: "compliance.service.api".to_string(),
                title: "Compliance Service Core Operations & Persistence".to_string(),
                category: ComplianceDocCategory::Service,
                summary: "API reference for the in-memory and persistent compliance service managing mapping snapshots.".to_string(),
                sections: vec![
                    ComplianceDocSection {
                        title: "Snapshot Operations".to_string(),
                        content: "Provides register, update status, assess framework compliance ratio, and verify PEP coverage.".to_string(),
                    },
                    ComplianceDocSection {
                        title: "Atomic Persistence".to_string(),
                        content: "Backs data with 1 MiB bounded JSON stores utilizing atomic rename and deterministic sorting.".to_string(),
                    },
                ],
                related_topics: vec![
                    "compliance.arch.overview".to_string(),
                    "compliance.observability.telemetry".to_string(),
                ],
            },
            ComplianceDocTopic {
                id: "compliance.policy.gates".to_string(),
                title: "Compliance Policy Enforcement & Security Gates".to_string(),
                category: ComplianceDocCategory::Policy,
                summary: "Security policy evaluating framework whitelisting, PEP gate verification, and compliance thresholds.".to_string(),
                sections: vec![
                    ComplianceDocSection {
                        title: "Enforcement Modes".to_string(),
                        content: "Supports 'audit_only' for permissive telemetry logging and 'enforce' for fail-closed execution blocking.".to_string(),
                    },
                    ComplianceDocSection {
                        title: "Gate Evaluation".to_string(),
                        content: "Evaluates mandatory frameworks, minimum compliance ratios, and threat ID coverage prior to privileged actions.".to_string(),
                    },
                ],
                related_topics: vec![
                    "compliance.lifecycle.states".to_string(),
                    "compliance.recovery.backup".to_string(),
                ],
            },
            ComplianceDocTopic {
                id: "compliance.observability.telemetry".to_string(),
                title: "Compliance Observability, Metrics & Telemetry".to_string(),
                category: ComplianceDocCategory::Observability,
                summary: "Telemetry aggregation and health monitoring for regulatory mappings across active workloads.".to_string(),
                sections: vec![
                    ComplianceDocSection {
                        title: "Observability Metrics".to_string(),
                        content: "Calculates framework status distributions, overall compliance ratios, capacity utilization, and policy modes.".to_string(),
                    },
                    ComplianceDocSection {
                        title: "Audit Correlation".to_string(),
                        content: "Integrates with SHA-256 hash-chained audit rings to guarantee non-repudiation of compliance assessments.".to_string(),
                    },
                ],
                related_topics: vec![
                    "compliance.service.api".to_string(),
                    "compliance.policy.gates".to_string(),
                ],
            },
            ComplianceDocTopic {
                id: "compliance.recovery.backup".to_string(),
                title: "Compliance Store Recovery & Snapshot Backup".to_string(),
                category: ComplianceDocCategory::Recovery,
                summary: "Disaster recovery, integrity checking, and snapshot restoration procedures for compliance stores.".to_string(),
                sections: vec![
                    ComplianceDocSection {
                        title: "Integrity Verification".to_string(),
                        content: "Validates schema versions, mapping count bounds (<= 1024), and UTF-8 encoding integrity.".to_string(),
                    },
                    ComplianceDocSection {
                        title: "Recovery Procedures".to_string(),
                        content: "Defines atomic fallback to canonical seed baselines when corruption or IO failure is detected.".to_string(),
                    },
                ],
                related_topics: vec![
                    "compliance.service.api".to_string(),
                    "compliance.arch.overview".to_string(),
                ],
            },
        ];
    }

    /// Lists all documentation topics.
    pub fn list_topics(&self) -> Vec<&ComplianceDocTopic> {
        self.topics.iter().collect()
    }

    /// Retrieves a specific topic by its unique identifier.
    pub fn get_topic(&self, id: &str) -> Result<&ComplianceDocTopic, String> {
        validate_topic_id(id).map_err(|code| format!("{}: invalid topic ID '{}'", code, id))?;
        self.topics
            .iter()
            .find(|t| t.id == id.trim())
            .ok_or_else(|| format!("{}: topic '{}' not found", COMPLYDOC_ERR_NOT_FOUND, id))
    }

    /// Searches documentation topics for query keywords with relevance ranking.
    pub fn search(&self, query: &str) -> Result<Vec<ComplianceDocSearchResult>, String> {
        let cleaned = sanitize_doc_query(query);
        if cleaned.is_empty() || query.trim().chars().count() > MAX_COMPLIANCE_DOC_QUERY_LEN {
            return Err(format!(
                "{}: query length must be between 1 and {} chars",
                COMPLYDOC_ERR_QUERY_BOUNDS, MAX_COMPLIANCE_DOC_QUERY_LEN
            ));
        }

        let query_lower = cleaned.to_lowercase();
        let tokens: Vec<&str> = query_lower.split_whitespace().collect();
        if tokens.is_empty() {
            return Err(format!("{}: search query contains no searchable tokens", COMPLYDOC_ERR_QUERY_BOUNDS));
        }

        let mut results = Vec::new();

        for topic in &self.topics {
            let mut score = 0;
            let mut best_snippet = String::new();

            // 1. Exact match on topic.id: +50 points
            if topic.id.to_lowercase() == query_lower {
                score += 50;
            }

            // 2. Match in topic.title: +25 points
            let title_lower = topic.title.to_lowercase();
            for token in &tokens {
                if title_lower.contains(token) {
                    score += 25;
                }
            }

            // 3. Match in topic.summary: +15 points
            let summary_lower = topic.summary.to_lowercase();
            for token in &tokens {
                if summary_lower.contains(token) {
                    score += 15;
                    if best_snippet.is_empty() {
                        best_snippet = topic.summary.clone();
                    }
                }
            }

            // 4. Match in sections: title (+5), content (+2)
            for section in &topic.sections {
                let sec_title_lower = section.title.to_lowercase();
                let sec_content_lower = section.content.to_lowercase();
                for token in &tokens {
                    if sec_title_lower.contains(token) {
                        score += 5;
                        if best_snippet.is_empty() {
                            best_snippet = format!("{}: {}", section.title, section.content);
                        }
                    }
                    if sec_content_lower.contains(token) {
                        score += 2;
                        if best_snippet.is_empty() {
                            best_snippet = section.content.clone();
                        }
                    }
                }
            }

            if score > 0 {
                let snippet = if best_snippet.is_empty() {
                    topic.summary.clone()
                } else if best_snippet.chars().count() > MAX_COMPLIANCE_DOC_SNIPPET_LEN {
                    format!("{}...", best_snippet.chars().take(MAX_COMPLIANCE_DOC_SNIPPET_LEN).collect::<String>())
                } else {
                    best_snippet
                };

                results.push(ComplianceDocSearchResult {
                    topic_id: topic.id.clone(),
                    title: topic.title.clone(),
                    category: topic.category,
                    score,
                    snippet,
                });
            }
        }

        // Sort descending by score, ascending by topic_id for determinism
        results.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.topic_id.cmp(&b.topic_id)));
        results.truncate(MAX_COMPLIANCE_DOC_SEARCH_RESULTS);

        Ok(results)
    }
}
