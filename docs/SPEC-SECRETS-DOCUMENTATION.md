# Specification: Secrets Handling Documentation (SPEC-SECRETS-DOCUMENTATION)

- **Status**: SPECIFIED
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Secrets Handling Documentation
- **Binding**: ADR-0035 §F-2

## 1. Overview
The Secrets Handling Documentation subsystem provides an embedded, offline reference manual and search engine for the AIOS secrets vault. It operates fully in-memory with zero external network or filesystem dependencies.

## 2. Topic Taxonomy & Categories
The repository organizes documentation topics into 6 canonical categories:
- `Architecture`: Vault structure, memory wiping, zero-disclosure rules.
- `Lifecycle`: Registration, retrieval, scope delegation, rotation, revocation.
- `Policy`: Security policy modes, payload bounds, prohibited kinds.
- `Observability`: Metrics aggregation, scope/kind distributions, health checks.
- `Security`: Threat model, CWE mitigations, memory defense.
- `Recovery`: Vault validation, corruption handling, atomic persistence.

## 3. Data Structures

```rust
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
```

## 4. Query Bounds & Error Constants
- `MAX_SECRET_DOC_QUERY_LEN = 128` (bytes)
- `MAX_SECRET_DOC_SEARCH_RESULTS = 10` (items)
- `MAX_SECRET_DOC_SNIPPET_LEN = 200` (bytes)
- `SECDOC_ERR_NOT_FOUND`: "SECDOC_ERR_NOT_FOUND"
- `SECDOC_ERR_QUERY_BOUNDS`: "SECDOC_ERR_QUERY_BOUNDS"

## 5. Scoring & Matching Rules
1. Exact match on `topic.id`: +100 points
2. Title contains keyword: +50 points
3. Summary contains keyword: +20 points
4. Section content contains keyword: +5 points
5. Search results sorted descending by score, capped at `MAX_SECRET_DOC_SEARCH_RESULTS`.
