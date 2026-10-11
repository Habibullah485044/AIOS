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
        if !self.related_topics.empty_or_placeholder() {
            md.push_str("### Related Topics\n\n");
            for rel in &self.related_topics {
                md.push_str(&format!("- `{}`\n", rel));
            }
        }
        md
    }
}

trait EmptyOrPlaceholder {
    fn empty_or_placeholder(&self) -> bool;
}

impl EmptyOrPlaceholder for Vec<String> {
    fn empty_or_placeholder(&self) -> bool {
        self.is_empty()
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
        Self::new()
    }
}

impl ComplianceDocRepository {
    pub fn new() -> Self {
        Self { topics: Vec::new() }
    }

    pub fn list_topics(&self) -> Vec<&ComplianceDocTopic> {
        self.topics.iter().collect()
    }

    pub fn get_topic(&self, _id: &str) -> Result<&ComplianceDocTopic, String> {
        // Scaffold stub (T-02945): fails loudly
        Err("not implemented: ComplianceDocRepository::get_topic (T-02945 scaffold)".to_string())
    }

    pub fn search(&self, _query: &str) -> Result<Vec<ComplianceDocSearchResult>, String> {
        // Scaffold stub (T-02945): fails loudly
        Err("not implemented: ComplianceDocRepository::search (T-02945 scaffold)".to_string())
    }
}
