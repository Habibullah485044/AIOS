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

#[derive(Debug, Clone)]
pub struct SecretDocRepository {
    topics: Vec<SecretDocTopic>,
}

impl Default for SecretDocRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretDocRepository {
    pub fn new() -> Self {
        Self { topics: Vec::new() }
    }

    pub fn list_topics(&self) -> Vec<&SecretDocTopic> {
        self.topics.iter().collect()
    }

    pub fn get_topic(&self, id: &str) -> Option<&SecretDocTopic> {
        self.topics.iter().find(|t| t.id == id)
    }

    pub fn search(&self, query: &str) -> Result<Vec<SecretDocSearchResult>, String> {
        let _ = query;
        Err("SecretDocRepository::search scaffolded for T-02683; implemented in T-02684".into())
    }
}
