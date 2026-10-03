# Specification: Threat Model Documentation (SPEC-THREAT-MODEL-DOCUMENTATION)

- **Status**: IMPLEMENTED & VERIFIED
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Threat Model Documentation
- **Binding**: ADR-0035 §H-1, ADR-0036 §D-1
- **Source Code**: [`code/aiosh-rust/aiosh-core/src/threat_model_doc.rs`](../code/aiosh-rust/aiosh-core/src/threat_model_doc.rs)
- **Unit Tests**: [`code/aiosh-rust/aiosh-core/tests/test_threat_model_doc.rs`](../code/aiosh-rust/aiosh-core/tests/test_threat_model_doc.rs)
- **Integration Tests**: [`code/aiosh-rust/aiosh-core/tests/test_threat_model_doc_integration.rs`](../code/aiosh-rust/aiosh-core/tests/test_threat_model_doc_integration.rs)

## 1. Overview
The Threat Model Documentation subsystem provides an embedded, offline reference manual and full-text search engine for Threat Model Maintenance within AIOS. It operates purely in-memory with compile-time seeded canonical knowledge, requiring zero network access and enforcing strict input bounds to prevent resource exhaustion and log injection.

## 2. Topic Taxonomy & Categories
The documentation index categorizes topics into 6 canonical domains:
- `Architecture`: STRIDE model taxonomy, trust boundaries, and kernel assets (`threat.arch.stride`).
- `Lifecycle`: Threat data model, state machine (`Identified` to `Resolved`), and transition rules (`threat.lifecycle.states`).
- `Service`: Core operations, threat registration, risk calculation, and atomic persistence (`threat.service.api`).
- `Policy`: Security policy modes (`Enforcing`/`Permissive`), CWE mapping enforcement, and critical threat guards (`threat.policy.gates`).
- `Observability`: Telemetry metrics, distribution aggregations, and audit ring correlation (`threat.observability.metrics`).
- `Recovery`: Emergency catalog restore, backup snapshots, and corruption mitigation (`threat.recovery.backup`).

## 3. Data Structures

```rust
pub const MAX_THREAT_DOC_QUERY_LEN: usize = 128;
pub const MAX_THREAT_DOC_SEARCH_RESULTS: usize = 10;
pub const MAX_THREAT_DOC_SNIPPET_LEN: usize = 200;

pub const THREATDOC_ERR_NOT_FOUND: &str = "THREATDOC_ERR_NOT_FOUND";
pub const THREATDOC_ERR_QUERY_BOUNDS: &str = "THREATDOC_ERR_QUERY_BOUNDS";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatDocSection {
    pub title: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatDocTopic {
    pub id: String,
    pub title: String,
    pub category: ThreatDocCategory,
    pub summary: String,
    pub sections: Vec<ThreatDocSection>,
    pub related_topics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatDocSearchResult {
    pub topic_id: String,
    pub title: String,
    pub category: ThreatDocCategory,
    pub score: usize,
    pub snippet: String,
}
```

## 4. Query Bounds & Scoring Rules
- Maximum query length: 128 characters (`MAX_THREAT_DOC_QUERY_LEN`).
- Maximum results returned: 10 items (`MAX_THREAT_DOC_SEARCH_RESULTS`).
- Maximum snippet length: 200 characters (`MAX_THREAT_DOC_SNIPPET_LEN`).
- Relevance Scoring:
  - Exact match on `topic.id`: +50 points
  - Match in `topic.title`: +25 points
  - Match in `topic.summary`: +15 points
  - Match in section title: +5 points
  - Match in section body: +2 points

## 5. Security Invariants
- `THREATDOC1`: Compile-time seeded topics with immutable reference data.
- `THREATDOC2`: Ranked search over tokens with deterministic score ordering.
- `THREATDOC3`: Bounded query length ($\le 128$) and result list ($\le 10$) to prevent CPU/memory exhaustion (CWE-400).
- `THREATDOC4`: Topic ID sanitization rejecting control characters, path traversal (`..`), directory separators, and injection delimiters (CWE-22, CWE-20).
- `THREATDOC5`: Complete coverage of all STRIDE categories, policy modes, and lifecycle states.

## 6. MCP Interface Design
Exposed via `aios.threat.doc`:
- `action: "list"`: Enumerate all topic IDs, titles, and categories.
- `action: "get"`: Retrieve topic details and sections by `id`.
- `action: "search"`: Query documentation topics with ranked keyword matching and snippets.
