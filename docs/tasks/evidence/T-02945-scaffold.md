# Scaffold Evidence: Compliance Mapping Documentation (T-02945)

- **Subsystem**: Phase 2 — Security Kernel & PEP Fabric / Compliance Mapping / Documentation
- **Task ID**: `T-02945`
- **Files Created / Modified**:
  - `code/aiosh-rust/aiosh-core/src/compliance_doc.rs` (created)
  - `code/aiosh-rust/aiosh-core/src/lib.rs` (registered `compliance_doc` module)
  - `code/aiosh-mcp/aiosh_mcp/compliance_doc.py` (created)
  - `code/aiosh-mcp/aiosh_mcp/compliance.py` (added `doc-list`, `doc-get`, `doc-search` actions and scaffold dispatch stub)
  - `code/aiosh-rust/aiosh-core/tests/test_compliance_doc_scaffold.rs` (created test stub)
  - `code/aiosh-mcp/tests/test_compliance_doc_scaffold.py` (created test stub)

## 1. Scaffolded Symbols & Interfaces

### 1.1 Constants & Types
- `COMPLYDOC_ERR_NOT_FOUND = "COMPLYDOC_ERR_NOT_FOUND"`
- `COMPLYDOC_ERR_QUERY_BOUNDS = "COMPLYDOC_ERR_QUERY_BOUNDS"`
- `MAX_COMPLIANCE_DOC_QUERY_LEN = 128`
- `MAX_COMPLIANCE_DOC_SEARCH_RESULTS = 10`
- `MAX_COMPLIANCE_DOC_SNIPPET_LEN = 200`
- `ComplianceDocCategory`: Architecture, Frameworks, Lifecycle, Service, Policy, Observability, Recovery
- `ComplianceDocSection`, `ComplianceDocTopic`, `ComplianceDocSearchResult`
- `ComplianceDocRepository`: `list_topics()`, `get_topic()`, `search()`
- MCP actions in `compliance.py`: `doc-list`, `doc-get`, `doc-search`

### 1.2 Verification Runs
- `cargo test --test test_compliance_doc_scaffold`: PASS
- `python -m pytest code/aiosh-mcp/tests/test_compliance_doc_scaffold.py`: PASS (2/2 passed)
