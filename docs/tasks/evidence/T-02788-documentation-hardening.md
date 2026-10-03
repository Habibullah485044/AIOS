# Hardening Evidence: Threat Model Documentation (T-02788)

## Overview
Documents hardening verification of the Threat Model Documentation subsystem (`code/aiosh-rust/aiosh-core/src/threat_model_doc.rs`), confirming query length limits, directory traversal and device name rejection, and bounded snippet sizing.

## Verified Hardening Assertions
1. **Query Length Boundary Enforcement (`THREATDOC3`, CWE-400)**:
   - Queries at exactly 128 characters succeed without error.
   - Queries at 129 characters fail closed immediately with `THREATDOC_ERR_QUERY_BOUNDS`.
2. **Path Traversal & Device Name Sanitization (`THREATDOC4`, CWE-22)**:
   - Directory climbing attempts (`../`, `..\\`, `threat..arch`) return `None`.
   - Sensitive OS paths (`/etc/shadow`, `C:\\Windows\\System32`) and Windows device names (`COM1`, `NUL`) are rejected.
   - Delimiters such as `<script>` and control characters (`\x7f`, null bytes) return `None`.
3. **Snippet Length Bounded Output**:
   - Snippet lengths strictly bounded to at most `MAX_THREAT_DOC_SNIPPET_LEN` (200 characters) + 3 suffix bytes (`...`).
4. **Result Set Bounded Cardinality**:
   - Search results strictly truncated to at most 10 items (`MAX_THREAT_DOC_SEARCH_RESULTS`).

## Test Verification Output
```text
running 7 tests
test test_threat_doc_canonical_topics_present ... ok
test test_threat_doc_get_topic ... ok
test test_threat_doc_hardening_and_boundary_checks ... ok
test test_threat_doc_list_by_category ... ok
test test_threat_doc_render_markdown ... ok
test test_threat_doc_search_boundaries ... ok
test test_threat_doc_search_scoring_and_ranking ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
```
