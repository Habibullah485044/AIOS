# Implementation Evidence: Compliance Mapping Documentation (T-02946)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Documentation
- **Task ID**: `T-02946`
- **Specification**: `docs/SPEC-COMPLIANCE-DOCUMENTATION.md`
- **Files Modified / Implemented**:
  - `code/aiosh-rust/aiosh-core/src/compliance_doc.rs`: Full implementation of canonical compliance topics, query sanitization, topic ID validation, relevance-ranked search, and markdown generator.
  - `code/aiosh-mcp/aiosh_mcp/compliance_doc.py`: Parity implementation of topics, bounds, relevance scoring, and repository in Python.
  - `code/aiosh-mcp/aiosh_mcp/compliance.py`: Wired `doc-list`, `doc-get`, and `doc-search` actions into `execute(...)` with `query` parameter.
  - `code/aiosh-mcp/aiosh_mcp/server.py`: Registered `query` parameter in `aios_compliance` MCP tool.
  - `code/aiosh-mcp/tests/test_compliance_surface.py`: Extended action sets to include `stats`, `doc-list`, `doc-get`, `doc-search`.

## 1. Implemented Features & Invariants

### 1.1 Canonical Knowledge Base (COMPLYDOC1, COMPLYDOC5)
- Seeded 7 canonical reference topics across all operational categories:
  1. `compliance.arch.overview` (Architecture)
  2. `compliance.frameworks.taxonomy` (Frameworks)
  3. `compliance.lifecycle.states` (Lifecycle)
  4. `compliance.service.api` (Service)
  5. `compliance.policy.gates` (Policy)
  6. `compliance.observability.telemetry` (Observability)
  7. `compliance.recovery.backup` (Recovery)

### 1.2 Query Bounds & Lexical Ranking (COMPLYDOC2, COMPLYDOC3)
- Bounded search query: $\le 128$ characters (`MAX_COMPLIANCE_DOC_QUERY_LEN`).
- Bounded result list: $\le 10$ entries (`MAX_COMPLIANCE_DOC_SEARCH_RESULTS`).
- Bounded text snippet: $\le 200$ characters (`MAX_COMPLIANCE_DOC_SNIPPET_LEN`).
- Relevance scoring: exact ID match (+50), title (+25), summary (+15), section title (+5), section body (+2).

### 1.3 Path Traversal & Injection Defense (COMPLYDOC4)
- Enforces strict validation rejecting `..`, `/`, `\`, null bytes, and ASCII/Unicode control characters in topic IDs.

## 2. Verification Runs
- `cargo check`: PASS (finished in 56s, 0 errors, 0 warnings)
- `python -m pytest code/aiosh-mcp/tests/test_compliance_surface.py code/aiosh-mcp/tests/test_compliance_observability_unit.py`: PASS (21/21 passed)
