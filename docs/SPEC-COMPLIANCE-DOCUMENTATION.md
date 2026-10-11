# Specification: Compliance Mapping Documentation (SPEC-COMPLIANCE-DOCUMENTATION)

- **Status**: IMPLEMENTED & VERIFIED
- **Date**: 2026-10-11
- **Subsystem**: Phase 2 Security Kernel & PEP Fabric / Compliance Mapping Documentation
- **Binding**: ADR-0035 §H-1, ADR-0037 §D-1
- **Source Code**:
  - Rust: [`code/aiosh-rust/aiosh-core/src/compliance_doc.rs`](../code/aiosh-rust/aiosh-core/src/compliance_doc.rs)
  - Python: [`code/aiosh-mcp/aiosh_mcp/compliance_doc.py`](../code/aiosh-mcp/aiosh_mcp/compliance_doc.py)
  - MCP Tool: [`code/aiosh-mcp/aiosh_mcp/compliance.py`](../code/aiosh-mcp/aiosh_mcp/compliance.py), [`code/aiosh-mcp/aiosh_mcp/server.py`](../code/aiosh-mcp/aiosh_mcp/server.py)
- **Unit Tests**:
  - Rust: [`code/aiosh-rust/aiosh-core/tests/test_compliance_doc_unit.rs`](../code/aiosh-rust/aiosh-core/tests/test_compliance_doc_unit.rs)
  - Python: [`code/aiosh-mcp/tests/test_compliance_doc_unit.py`](../code/aiosh-mcp/tests/test_compliance_doc_unit.py)
- **Integration Tests**:
  - Rust: [`code/aiosh-rust/aiosh-core/tests/test_compliance_doc_integration.rs`](../code/aiosh-rust/aiosh-core/tests/test_compliance_doc_integration.rs)
  - Python: [`code/aiosh-mcp/tests/test_compliance_doc_integration.py`](../code/aiosh-mcp/tests/test_compliance_doc_integration.py)
- **Hardening Tests**:
  - Rust: [`code/aiosh-rust/aiosh-core/tests/test_compliance_doc_hardening.rs`](../code/aiosh-rust/aiosh-core/tests/test_compliance_doc_hardening.rs)
  - Python: [`code/aiosh-mcp/tests/test_compliance_doc_hardening.py`](../code/aiosh-mcp/tests/test_compliance_doc_hardening.py)

---

## 1. Overview

The Compliance Mapping Documentation subsystem provides an embedded, offline reference repository and relevance-ranked search engine for Regulatory Compliance Mapping within AIOS. It operates purely in-memory with compile-time seeded canonical knowledge, requiring zero network access and enforcing strict input bounds to prevent resource exhaustion (CWE-400) and injection attacks (CWE-22, CWE-20).

---

## 2. Topic Taxonomy & Categories

The documentation index categorizes topics into canonical domains:
- `Architecture`: Compliance mapping architecture, substrate target bindings, and data models (`compliance.arch.overview`).
- `Frameworks`: Regulatory framework taxonomies (NIST SP 800-53 Rev 5, ISO 27001:2022, SOC 2 Type II, CIS Controls v8) (`compliance.frameworks.taxonomy`).
- `Lifecycle`: Compliance mapping lifecycle states (`Compliant`, `PartiallyCompliant`, `NonCompliant`, `NotApplicable`) and transition gates (`compliance.lifecycle.states`).
- `Service`: Core compliance service operations, store persistence, assessment calculation, and PEP coverage verification (`compliance.service.api`).
- `Policy`: Security policy gating rules, framework whitelisting, threat linking, and threshold evaluation (`compliance.policy.gates`).
- `Observability`: Telemetry metrics aggregation, distribution metrics, capacity utilization, and audit ring correlation (`compliance.observability.telemetry`).
- `Recovery`: Atomic store recovery, backup snapshotting, and validation protocols (`compliance.recovery.backup`).

---

## 3. Data Structures & Constants

```rust
pub const MAX_COMPLIANCE_DOC_QUERY_LEN: usize = 128;
pub const MAX_COMPLIANCE_DOC_SEARCH_RESULTS: usize = 10;
pub const MAX_COMPLIANCE_DOC_SNIPPET_LEN: usize = 200;

pub const COMPLYDOC_ERR_NOT_FOUND: &str = "COMPLYDOC_ERR_NOT_FOUND";
pub const COMPLYDOC_ERR_QUERY_BOUNDS: &str = "COMPLYDOC_ERR_QUERY_BOUNDS";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceDocSection {
    pub title: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceDocTopic {
    pub id: String,
    pub title: String,
    pub category: ComplianceDocCategory,
    pub summary: String,
    pub sections: Vec<ComplianceDocSection>,
    pub related_topics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceDocSearchResult {
    pub topic_id: String,
    pub title: String,
    pub category: ComplianceDocCategory,
    pub score: usize,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceDocRepository {
    pub topics: Vec<ComplianceDocTopic>,
}
```

---

## 4. Query Bounds & Scoring Rules

- Maximum query length: 128 characters (`MAX_COMPLIANCE_DOC_QUERY_LEN`).
- Maximum results returned: 10 items (`MAX_COMPLIANCE_DOC_SEARCH_RESULTS`).
- Maximum snippet length: 200 characters (`MAX_COMPLIANCE_DOC_SNIPPET_LEN`).
- Relevance Scoring:
  - Exact match on `topic.id`: +50 points
  - Match in `topic.title`: +25 points
  - Match in `topic.summary`: +15 points
  - Match in section title: +5 points
  - Match in section body: +2 points
- Deterministic Ordering: Primary by `score` descending, secondary by `topic_id` ascending.

---

## 5. Security Invariants

- `COMPLYDOC1`: Pre-seeded in-memory repository with immutable reference data.
- `COMPLYDOC2`: Ranked search over tokens with deterministic score ordering.
- `COMPLYDOC3`: Bounded query length ($\le 128$) and result list ($\le 10$) to prevent resource exhaustion (CWE-400).
- `COMPLYDOC4`: Topic ID sanitization rejecting control characters, path traversal (`..`), directory separators, and injection delimiters (CWE-22, CWE-20).
- `COMPLYDOC5`: Complete coverage of all supported regulatory frameworks, policy modes, and lifecycle states.

---

## 6. MCP Interface Design

Exposed via `aios.compliance` tool:
- `action: "doc-list"`: Enumerate all topic IDs, titles, and categories.
- `action: "doc-get"`: Retrieve topic details and sections by `id`.
- `action: "doc-search"`: Query documentation topics with ranked keyword matching and snippets.
- All doc actions are read-only: do not mutate store, require no capability grant, and emit an honest audit row.

---

## 7. Hardening & Security Controls

- **Unicode & Bidi Sanitization**: Strips bidirectional text override codepoints (`\u{202A}`..`\u{202E}`), invisible formatting marks (`\u{2060}`..`\u{2069}`), zero-width characters (`\u{200B}`..`\u{200F}`), and byte-order marks (`\u{FEFF}`).
- **Topic ID Boundary Rules**: Topic IDs must strictly adhere to `[a-zA-Z0-9._-]` and cannot start or end with dots (`.`) or hyphens (`-`).
- **Empty Query Collapse**: Queries consisting solely of invisible/control characters collapse to empty queries and trigger `COMPLYDOC_ERR_QUERY_BOUNDS` instead of performing unindexed scans.

---

## 8. Verification & Evidence Summary

- Full dual-substrate test coverage (Rust + Python).
- Clean static analysis: zero errors, zero warnings.
- Proof-of-Restraint invariant `I-2` certified.
