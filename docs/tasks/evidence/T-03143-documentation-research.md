# Research & Security Audit Evidence: AI Control Plane MCP Server Core Documentation (T-03143)

- **Subsystem**: Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / documentation
- **Artifact**: `docs/tasks/evidence/T-03143-documentation-research.md`
- **Bindings**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2, SPEC-MCP-SERVER-CORE-API

---

## 1. Facts, Constraints, and Prior Art

### 1.1 Established Facts (Authoritative)
1. **MCP Self-Documentation Role**:
   - The Model Context Protocol specification requires tools and resources to expose structured metadata (name, description, schema).
   - In AIOS, autonomous agents and operators require rich, self-contained documentation lookup directly over the MCP transport without external network dependencies or unvetted filesystem access.
2. **Prior Art in Subsystems**:
   - `compliance_doc.py` and `incident_runbook_doc.py` established standardized in-memory indexed documentation catalogs.
   - Topics are structured with `topic_id`, `title`, `category`, `summary`, `content`, `keywords`, and `cross_references`.
3. **Dual-Substrate Architecture**:
   - Python substrate (`aiosh_mcp.mcp_server_core_doc`): Provides in-memory topic catalog, full-text keyword search index, and FastMCP tool registration.
   - Rust substrate (`aiosh-core::mcp_server_core_doc`): High-efficiency compiled documentation registry with zero-allocation retrieval and topic validation.
4. **Security & Proof-of-Restraint Gating**:
   - Documentation queries are strictly read-only (`READ_ONLY` action category).
   - In accordance with Proof-of-Restraint Invariant I-2, doc queries require no elevated capability tokens and produce no mutable side-effects on disk.
   - No sensitive information (e.g. private keys, unredacted passwords, internal memory pointers) may be embedded in documentation records.

### 1.2 Identified Assumptions (vs. Facts)
1. *Assumption*: Autonomous agents can discover all tool behaviors purely from schema description fields.
   - *Fact*: JSON Schema descriptions are limited to brief descriptions. Detailed usage examples, error envelopes, and invariant rules require dedicated documentation topics.
2. *Assumption*: Searching documentation requires heavy external search engines (e.g., Elasticsearch or SQLite FTS5).
   - *Fact*: A lightweight, deterministic in-memory keyword matching index is sufficient, zero-dependency, and eliminates denial-of-service risks.

### 1.3 Constraints & Boundaries
1. **Query Length & Search Results Bounds**:
   - Query strings must be capped at 128 characters (`MAX_MCP_DOC_QUERY_LEN = 128`).
   - Search results must be bounded at a maximum of 10 matches (`MAX_MCP_DOC_SEARCH_RESULTS = 10`) to prevent denial-of-service via large payloads.
2. **Sanitization**:
   - Queries must be sanitized using `sanitize_doc_query()`, stripping control characters (`\x00..\x1f`), ASCII DEL, and bidirectional/invisible Unicode codepoints (`\u200b`, `\ufeff`, etc.).
3. **Topic Identifier Validation**:
   - Topic IDs must prevent directory traversal (`..`, `/`, `\`), NUL bytes (`\0`), and control characters fail-closed.

---

## 2. Invariant Specifications (MCPDOC-INV1..MCPDOC-INV5)

- **`MCPDOC-INV1` (Query Bounds)**: Search query strings > 128 characters are rejected or clamped fail-safe.
- **`MCPDOC-INV2` (Result Clamping)**: Search results return at most 10 structured summaries.
- **`MCPDOC-INV3` (Fail-Closed Traversal Protection)**: Any topic lookup containing path traversal characters (`..`, `/`, `\`) or NUL bytes raises `MCPDOC_ERR_INVALID_ID` or `MCPDOC_ERR_NOT_FOUND`.
- **`MCPDOC-INV4` (Zero Mutation Guarantee)**: Documentation lookups and searches never mutate filesystem, database, or runtime state.
- **`MCPDOC-INV5` (PoR Invariant I-2)**: Pure read-only operation requiring no capability tokens and causing zero privilege escalation.

---

## 3. Decisions & Implementation Roadmap

- **Decision 1**: Create `code/aiosh-mcp/aiosh_mcp/mcp_server_core_doc.py` containing the core topic catalog (wire API, configuration, automated tests, security policy, observability, and lifecycle) and search engine.
- **Decision 2**: Create `code/aiosh-rust/aiosh-core/src/mcp_server_core_doc.rs` for Rust substrate parity.
- **Decision 3**: Expose FastMCP tool `aios_mcp_doc_lookup` supporting `topic_id` lookup and `query` search.
- **Decision 4**: No code changes in this research task; all implementation begins in scaffold (`T-03145`) and implementation (`T-03146`).
