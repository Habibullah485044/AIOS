# Specification: Secrets Handling Documentation (SPEC-SECRETS-DOCUMENTATION)

- **Status**: IMPLEMENTED & HARDENED
- **Date**: 2026-10-03
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Secrets Handling Documentation
- **Binding**: ADR-0035 §F-2

## 1. Overview
The Secrets Handling Documentation subsystem provides an embedded, offline reference manual and search engine for the AIOS secrets vault. It operates fully in-memory with zero external network or filesystem dependencies, adhering to the Zero-Disclosure Invariant and strict input sanitization.

## 2. Topic Taxonomy & Categories
The repository organizes documentation topics into 6 canonical categories:
- `Architecture`: Vault structure, memory wiping, zero-disclosure rules (`secrets-overview`).
- `Lifecycle`: Registration, retrieval, scope delegation, rotation, revocation (`secrets-lifecycle`).
- `Policy`: Security policy modes, payload bounds, prohibited kinds (`secrets-policy`).
- `Observability`: Metrics aggregation, scope/kind distributions, health checks (`secrets-observability`).
- `Security`: Threat model, CWE mitigations, memory defense (`secrets-security`).
- `Recovery`: Vault validation, corruption handling, atomic persistence (`secrets-recovery`).

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
1. Match on `topic.id`: +50 points per token
2. Title contains keyword: +25 points per token
3. Summary contains keyword: +15 points per token
4. Section title contains keyword: +5 points per token
5. Section content contains keyword: +2 points per token
6. Search results sorted descending by score, capped at `MAX_SECRET_DOC_SEARCH_RESULTS`.

## 6. CLI Interface Reference
The operator CLI provides subcommands under `aiosh secret doc`:

```bash
# List all registered topics
aiosh secret doc list
aiosh secret doc list --json

# Retrieve and render a topic in Markdown
aiosh secret doc get secrets-overview
aiosh secret doc get --id secrets-policy --json

# Search documentation topics with relevance ranking
aiosh secret doc search encryption
aiosh secret doc search --query "vault rotation" --json
```

## 7. Security Invariants
- **Zero-Disclosure Invariant**: Documentation examples contain synthetic dummy values, never real secrets.
- **Path Hygiene & Injection Defense**: Topic IDs and search queries are checked against control characters, path climbing (`..`, `/`, `\`), and HTML markup delimiters (`<`, `>`).
- **Terminal Sanitization**: All human-readable terminal output is scrubbed with `sanitize_terminal()` to prevent ANSI escape sequence injection.
- **Audit Logging**: Doc access and search operations emit audit ring records via `classify_and_emit()`.

## 8. Evidence Links
- Research: `docs/tasks/evidence/T-02681-documentation-research.md`
- Specification: `docs/tasks/evidence/T-02682-documentation-specification.md`
- Unit Tests: `docs/tasks/evidence/T-02685-documentation-unit-test.md`
- Integration: `docs/tasks/evidence/T-02686-documentation-integration.md`
- Security Review: `docs/tasks/evidence/T-02687-documentation-security-review.md`
- Hardening: `docs/tasks/evidence/T-02688-documentation-hardening.md`
