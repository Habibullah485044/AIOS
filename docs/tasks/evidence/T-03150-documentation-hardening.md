# Hardening Evidence: AI Control Plane MCP Server Core Documentation (T-03150)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / documentation
- **Artifact**: `docs/tasks/evidence/T-03150-documentation-hardening.md`
- **Modules Hardened**:
  - `code/aiosh-mcp/aiosh_mcp/mcp_server_core_doc.py`
  - `code/aiosh-rust/aiosh-core/src/mcp_server_core_doc.rs`
  - `code/aiosh-mcp/tests/test_mcp_server_core_doc_hardening.py`

---

## 1. Hardening Defenses Applied

1. **Unicode NFKC Normalization**:
   - Both `sanitize_doc_query` and `validate_topic_id` execute `unicodedata.normalize("NFKC", ...)` to prevent full-width, homoglyph, or composite character bypasses.
2. **Topic Catalog Capacity Limit (CWE-770 Defense)**:
   - Enforced hard ceiling of `MAX_TOPICS_LIMIT = 256` in both Python and Rust catalog registries.
   - Any attempt to exceed the cap raises `MCPDOC_ERR_CAPACITY`.
3. **Information Disclosure & Path Redaction (CWE-209 Defense)**:
   - Wrapped `aios_mcp_doc_lookup` exceptions with path sanitization (`[REDACTED_PATH]`) and truncated messages to 200 characters to prevent leaking stack traces or host filesystem details.
4. **Automated Verification**:
   - `test_mcp_server_core_doc_hardening.py` (3 passed).
   - Entire documentation test suite: 19/19 tests PASSED.
