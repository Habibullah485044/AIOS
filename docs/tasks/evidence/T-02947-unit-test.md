# Unit Test Evidence: Compliance Mapping Documentation (T-02947)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Documentation
- **Task ID**: `T-02947`
- **Specification**: `docs/SPEC-COMPLIANCE-DOCUMENTATION.md`
- **Test Files**:
  - `code/aiosh-rust/aiosh-core/tests/test_compliance_doc_unit.rs`
  - `code/aiosh-mcp/tests/test_compliance_doc_unit.py`

## 1. Test Coverage & Verification

### 1.1 Canonical Topics Enumeration & Integrity (COMPLYDOC1, COMPLYDOC5)
- Verified all 7 canonical topics are enumerated with expected IDs, categories, and titles.
- Validated positive topic retrieval and markdown rendering.

### 1.2 Path Traversal & Injection Defense (COMPLYDOC4)
- Verified rejection of empty IDs, path traversal (`../etc/passwd`), directory separators (`/`), null bytes (`\0`), and control characters.
- Certified error code `COMPLYDOC_ERR_NOT_FOUND`.

### 1.3 Query Sanitization, Bounds & Error Codes (COMPLYDOC3)
- Verified control characters are stripped.
- Verified queries $\le 128$ characters are permitted; queries $> 128$ characters or empty/whitespace are rejected with `COMPLYDOC_ERR_QUERY_BOUNDS`.

### 1.4 Relevance Scoring & Determinism (COMPLYDOC2)
- Tested exact ID (+50), title match (+25), summary match (+15), and section match (+2..+5).
- Verified deterministic ordering (score DESC, topic_id ASC) and max results bounding (10 items).

### 1.5 MCP Surface Actions
- Tested `doc-list`, `doc-get`, and `doc-search` actions via `execute(...)`.

## 2. Execution Results
- `cargo test --test test_compliance_doc_unit`: PASS (7/7 passed)
- `python -m pytest code/aiosh-mcp/tests/test_compliance_doc_unit.py`: PASS (7/7 passed)
