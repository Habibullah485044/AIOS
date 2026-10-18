# Specification: AI Control Plane MCP Server Core Documentation Subsystem

**Document ID**: SPEC-MCP-SERVER-CORE-DOC  
**Lifecycle Target**: T-03143..T-03152 (Phase 3 — AI Control Plane (Pillar C Spine) / MCP Server Core / documentation)  
**Contract Reference**: ADR-0035 §D-2, ADR-0035 §AF-2, PoR Invariant I-2  
**Status**: ACTIVE  

---

## 1. Overview & Architectural Role

The **MCP Server Core Documentation Subsystem** provides a zero-dependency, self-contained reference repository and topic search index for autonomous agents and operators. It documents protocol wire framing, configuration parameters, test suites, security policy rules, and observability telemetry directly over the Model Context Protocol.

Both Python (`aiosh_mcp.mcp_server_core_doc`) and Rust (`aiosh_core::mcp_server_core_doc`) implement this specification with byte-level schema parity.

---

## 2. Documentation Invariants & Contracts

| Invariant | Field / Target | Type | Bounds / Validation | Description |
| :--- | :--- | :--- | :--- | :--- |
| **MCPDOC-INV1** | `query` | `String` | Length $\le 128$, sanitized | Maximum search query string length |
| **MCPDOC-INV2** | `results` | `List[TopicSummary]` | Length $\le 10$ | Maximum returned search results |
| **MCPDOC-INV3** | `topic_id` | `String` | `^[a-zA-Z0-9_\-\.]{1,64}$`, no `..`, `/`, `\` | Topic identifier traversal immunity |
| **MCPDOC-INV4** | `content` | `String` | Non-empty, no unredacted secrets | Safe documentation body text |
| **MCPDOC-INV5** | Read-Only Invariant | Trait / FastMCP | Pure query | No mutations to audit DB or files |

---

## 3. Data Model

### 3.1 `McpDocTopic`
- `topic_id`: Unique identifier (e.g., `"core.overview"`, `"core.policy"`).
- `title`: Short human-readable title.
- `category`: Category string (`"architecture"`, `"api"`, `"configuration"`, `"testing"`, `"security"`, `"observability"`).
- `summary`: One-line summary (up to 256 characters).
- `content`: Markdown-formatted documentation body.
- `keywords`: List of search keyword strings.
- `cross_references`: List of related `topic_id` references.

### 3.2 `McpDocSearchResult`
- `topic_id`: Matching topic ID.
- `title`: Matching topic title.
- `category`: Topic category.
- `summary`: Topic summary snippet.
- `score`: Relevance score integer ($\ge 1$).

---

## 4. Error Codes & Envelopes

- `MCPDOC_ERR_NOT_FOUND`: Specified `topic_id` does not exist in documentation catalog.
- `MCPDOC_ERR_INVALID_ID`: Topic ID contains forbidden characters, path traversal tokens (`..`), or NUL bytes.
- `MCPDOC_ERR_QUERY_BOUNDS`: Query string exceeds length bounds.
