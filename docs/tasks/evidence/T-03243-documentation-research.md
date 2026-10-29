# Research Evidence: AI Control Plane Model Backend Adapters Documentation (T-03243)

**Task ID**: T-03243 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / documentation: Research)  
**Contract Reference**: ADR-0035 §AF-2, ADR-0037, PoR Invariant I-2, `mcp_server_core_doc.py`  
**Date**: 2026-10-29  
**Author**: Codebuff (Antigravity Autonomous Pair)  
**Status**: PASSED — Documentation facts, constraints, prior art, and architectural decisions established.

---

## 1. Facts vs Assumptions

### 1.1 Established Facts (Codebase & Prior Art)
1. **Existing Patterns**: AIOS MCP subsystems implement an in-memory documentation catalog (`DocCatalog`, `DocTopic`) with full-text keyword search, topic categorization, and NFKC sanitization.
2. **Proof-of-Restraint Invariant I-2**: Reference documentation lookup and schema search are read-only operations consuming 0 capability tokens.
3. **Safety & Injection Defense**:
   - Topic identifiers must be strictly validated against regex `^[a-zA-Z0-9_\-\.]{1,64}$`.
   - Path traversal tokens (`..`, `/`, `\`) and NUL bytes (`\0`) must be rejected fail-closed to prevent local file inclusion or traversal attacks.
   - Queries must be sanitized against invisible unicode codepoints (Bidi overrides, zero-width spaces `\u200b`, BOM `\ufeff`).
4. **Information Redaction**: Error payloads and topic content must never leak local filesystem paths or live environment variable secrets.

### 1.2 Assumptions (Explicitly Listed)
1. **In-Memory Catalog**: Reference topics for Model Backend Adapters (OpenAI, Anthropic, Gemini, Ollama, Mock, Fallbacks, Security Policy, Observability) are bundled statically in-memory for zero disk I/O overhead.
2. **FastMCP Exposure**: The catalog is queryable via `aios_model_doc_get` and `aios_model_doc_search` MCP tools.

---

## 2. Authoritative Sources & Citations

- **ADR-0035 §AF-2**: Standard result envelope definitions (`status`, `ok`, `data`, `error_code`, `error_message`, `timestamp`).
- **ADR-0037**: Proof-of-Restraint standing rules and zero-token consumption for documentation queries.
- **`code/aiosh-mcp/aiosh_mcp/mcp_server_core_doc.py`**: Canonical topic indexing, query sanitization, and traversal validation patterns.

---

## 3. Decisions Needed Before Implementation (T-03244 Spec)

1. **Topic Taxonomy**:
   - `model.overview`: Architectural overview of Pillar C model adapters.
   - `model.providers`: Detailed documentation on supported providers (Mock, OpenAI, Anthropic, Gemini, Ollama).
   - `model.fallback`: Multi-stage fallback progression and retry policies.
   - `model.security`: Capability token gating, Invariant I-2, and input sanitization.
   - `model.observability`: Metrics snapshots, token conservation, and health classification.
2. **Search Scoring Mechanism**:
   - Weighted keyword matching (title match = 10 pts, tag match = 5 pts, body match = 1 pt).
3. **Capacity Constraints**:
   - Query length bounded at 128 characters.
   - Search results capped at at most 10 matches.
   - Max catalog capacity capped at 256 topics.
