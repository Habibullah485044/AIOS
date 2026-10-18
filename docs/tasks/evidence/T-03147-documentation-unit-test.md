# Unit Test Evidence: AI Control Plane MCP Server Core Documentation (T-03147)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / documentation
- **Artifact**: `docs/tasks/evidence/T-03147-documentation-unit-test.md`
- **Test Suites Created & Verified**:
  - Python: `code/aiosh-mcp/tests/test_mcp_server_core_doc_unit.py` (5 passed)
  - Rust: `code/aiosh-rust/aiosh-core/tests/test_mcp_server_core_doc_unit.rs` (3 passed)

---

## 1. Unit Test Matrix

| Invariant | Test Target | Verification Details | Result |
| :--- | :--- | :--- | :--- |
| **`MCPDOC-INV1`** | `sanitize_doc_query` | Query clamped to 128 chars; stripped invisible Unicode & control codes | **PASS** |
| **`MCPDOC-INV2`** | `search` | Result count clamped to `MAX_MCP_DOC_SEARCH_RESULTS = 10` | **PASS** |
| **`MCPDOC-INV3`** | `validate_topic_id` | Traversal sequences (`..`), slashes, NUL bytes, and syntax violations rejected | **PASS** |
| **`MCPDOC-INV4`** | `build_default_doc_catalog` | All 7 canonical topics populated, valid markdown, non-empty summaries, zero secrets | **PASS** |
| **`MCPDOC-INV5`** | `search` scoring | Multi-keyword relevance scoring and strictly descending rank order verified | **PASS** |
