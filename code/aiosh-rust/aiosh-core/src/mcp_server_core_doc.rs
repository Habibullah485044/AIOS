//! AI Control Plane MCP Server Core Documentation Subsystem (T-03145 scaffold / T-03146 impl).
//!
//! Provides in-memory topic catalog, keyword search index, and schema discovery
//! in compliance with SPEC-MCP-SERVER-CORE-DOC and Proof-of-Restraint Invariant I-2.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const MAX_MCP_DOC_QUERY_LEN: usize = 128;
pub const MAX_MCP_DOC_SEARCH_RESULTS: usize = 10;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpDocError {
    NotFound(String),
    InvalidId(String),
    QueryBounds(String),
}

impl std::fmt::Display for McpDocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpDocError::NotFound(s) => write!(f, "MCPDOC_ERR_NOT_FOUND: {}", s),
            McpDocError::InvalidId(s) => write!(f, "MCPDOC_ERR_INVALID_ID: {}", s),
            McpDocError::QueryBounds(s) => write!(f, "MCPDOC_ERR_QUERY_BOUNDS: {}", s),
        }
    }
}

impl std::error::Error for McpDocError {}

pub fn sanitize_doc_query(s: &str) -> String {
    let mut cleaned = String::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        if cp < 32 || (127..=159).contains(&cp) || is_invisible_codepoint(cp) {
            continue;
        }
        cleaned.push(c);
    }
    let trimmed = cleaned.trim();
    if trimmed.chars().count() > MAX_MCP_DOC_QUERY_LEN {
        trimmed.chars().take(MAX_MCP_DOC_QUERY_LEN).collect()
    } else {
        trimmed.to_string()
    }
}

fn is_invisible_codepoint(cp: u32) -> bool {
    matches!(
        cp,
        0x200B
            | 0x200C
            | 0x200D
            | 0x200E
            | 0x200F
            | 0x202A
            | 0x202B
            | 0x202C
            | 0x202D
            | 0x202E
            | 0x2060
            | 0x2061
            | 0x2062
            | 0x2063
            | 0x2064
            | 0x2066
            | 0x2067
            | 0x2068
            | 0x2069
            | 0xFEFF
    )
}

pub fn validate_topic_id(topic_id: &str) -> Result<(), McpDocError> {
    let trimmed = topic_id.trim();
    if trimmed.is_empty() {
        return Err(McpDocError::InvalidId("empty topic ID".into()));
    }
    if trimmed.contains('\0')
        || trimmed.contains("..")
        || trimmed.contains('/')
        || trimmed.contains('\\')
    {
        return Err(McpDocError::InvalidId(
            "forbidden path or traversal character in topic ID".into(),
        ));
    }
    if trimmed.len() > 64 {
        return Err(McpDocError::InvalidId(
            "topic ID exceeds maximum length of 64".into(),
        ));
    }
    for c in trimmed.chars() {
        if !c.is_ascii_alphanumeric() && c != '_' && c != '-' && c != '.' {
            return Err(McpDocError::InvalidId(format!(
                "forbidden character '{}' in topic ID",
                c
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpDocTopic {
    pub topic_id: String,
    pub title: String,
    pub category: String,
    pub summary: String,
    pub content: String,
    pub keywords: Vec<String>,
    pub cross_references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpDocSearchResult {
    pub topic_id: String,
    pub title: String,
    pub category: String,
    pub summary: String,
    pub score: usize,
}

#[derive(Debug, Default)]
pub struct McpServerCoreDocCatalog {
    topics: HashMap<String, McpDocTopic>,
}

impl McpServerCoreDocCatalog {
    pub fn new() -> Self {
        Self {
            topics: HashMap::new(),
        }
    }

    pub fn register(&mut self, topic: McpDocTopic) -> Result<(), McpDocError> {
        validate_topic_id(&topic.topic_id)?;
        self.topics.insert(topic.topic_id.clone(), topic);
        Ok(())
    }

    pub fn get(&self, topic_id: &str) -> Result<&McpDocTopic, McpDocError> {
        validate_topic_id(topic_id)?;
        self.topics
            .get(topic_id)
            .ok_or_else(|| McpDocError::NotFound(format!("topic '{}' not found", topic_id)))
    }

    pub fn search(&self, query: &str) -> Vec<McpDocSearchResult> {
        let sanitized = sanitize_doc_query(query).to_lowercase();
        if sanitized.is_empty() {
            return Vec::new();
        }
        let tokens: Vec<&str> = sanitized.split_whitespace().collect();
        let mut results = Vec::new();

        for topic in self.topics.values() {
            let mut score = 0;
            let searchable = format!(
                "{} {} {} {}",
                topic.topic_id,
                topic.title,
                topic.summary,
                topic.keywords.join(" ")
            )
            .to_lowercase();

            for &token in &tokens {
                if searchable.contains(token) {
                    score += 1;
                }
            }

            if score > 0 {
                results.push(McpDocSearchResult {
                    topic_id: topic.topic_id.clone(),
                    title: topic.title.clone(),
                    category: topic.category.clone(),
                    summary: topic.summary.clone(),
                    score,
                });
            }
        }

        results.sort_by(|a, b| b.score.cmp(&a.score));
        results.truncate(MAX_MCP_DOC_SEARCH_RESULTS);
        results
    }

    pub fn list_topics(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.topics.keys().cloned().collect();
        ids.sort();
        ids
    }
}
