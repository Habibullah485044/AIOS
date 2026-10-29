# T-03247 Evidence: Model Backend Adapters Documentation Unit Test

## Task Metadata
- Task ID: T-03247
- Title: Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / documentation: Unit Test
- Status: Completed
- Date: 2026-10-29

## Overview
Created focused automated unit test battery for Model Backend Adapters documentation in `code/aiosh-mcp/tests/test_model_backend_adapters_doc_unit.py`.

## Test Coverage
1. **Topic Validation**:
   - Valid topic ID permutations (alphanumeric, dot, dash, underscore, 64-char boundary)
   - Traversal attack rejection (`../traversal`, `..\traversal`, `/etc/passwd`, `\windows\system32`)
   - Syntax injection rejection (`<script>`, `;drop`, `$`, spaces, NUL bytes, length > 64)
2. **Query Sanitization**:
   - Stripping of invisible & Bidi override codepoints (ZWSP, BOM, RLO)
   - Stripping of ASCII control codes (<32, 127-159)
   - NFKC unicode normalization
   - Clamping at MAX_DOC_QUERY_LEN (128 characters)
3. **Catalog Lookups**:
   - Verification of 5 standard topics (`model.overview`, `model.providers`, `model.fallback`, `model.security`, `model.observability`)
   - Non-existent topic returns None
   - Traversal attack raises `ValueError(MODDOC_ERR_INVALID_ID)`
   - Catalog listing order and schema verification
   - Dict conversion immutability
4. **Search and Ranking**:
   - Relevance scoring (title, tags, summary, body, exact ID)
   - Search result bounds clamping (at MAX_DOC_SEARCH_RESULTS=10)
   - Sanitized queries with embedded control characters
   - Empty queries handling

## Verification
- Test run: 36 passed in 1.72s.
