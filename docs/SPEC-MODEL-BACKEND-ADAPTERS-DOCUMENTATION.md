# Specification: AI Control Plane Model Backend Adapters Documentation Subsystem

**Document ID**: SPEC-MODEL-BACKEND-ADAPTERS-DOCUMENTATION  
**Lifecycle Target**: T-03243..T-03252 (Phase 3 — AI Control Plane (Pillar C Spine) / Model Backend Adapters / documentation)  
**Contract Reference**: ADR-0035 §AF-2, ADR-0037, PoR Invariant I-2  
**Status**: APPROVED / ACTIVE  

---

## 1. Overview & Architectural Role

The **Model Backend Adapters Documentation Subsystem** provides an in-memory, zero-dependency reference catalog, keyword search engine, and schema inspection mechanism for model backend adapters in AIOS.

It enables operators, scripts, and autonomous LLM agents to programmatically query adapter specifications, provider capabilities, parameter constraints, fallback chains, and security policies without external network calls or disk lookups.

---

## 2. Invariants & Certified Contracts

| Invariant | Target | Rule | Description |
| :--- | :--- | :--- | :--- |
| **`MODDOC-INV1`** | Proof-of-Restraint (PoR Invariant I-2) | Zero tokens consumed | Topic queries, catalog enumeration, and keyword search require 0 capability tokens. |
| **`MODDOC-INV2`** | Sanitization & Injection Defense | Query normalization | Strips ASCII control codes (<32, 127), Bidi control overrides, and zero-width spaces (`\u200b`, `\ufeff`). Queries clamped to 128 characters. |
| **`MODDOC-INV3`** | Traversal Immunity | Strict Identifier Syntax | Topic identifiers must match `^[a-zA-Z0-9_\-\.]{1,64}$`. Path traversal tokens (`..`, `/`, `\`) and NUL bytes (`\0`) rejected fail-closed. |
| **`MODDOC-INV4`** | ADR-0035 §AF-2 Envelopment | Uniform return types | All lookups and searches return `{status, ok, data/topics, error_code, error_message}`. |
| **`MODDOC-INV5`** | Bounded Catalog & Output | Capacity ceilings | Search results capped at 10 items; catalog bounded at 256 topics. |

---

## 3. Data Models & Interface Contracts

### 3.1 `ModelAdapterDocTopic`
```python
@dataclass(frozen=True)
class ModelAdapterDocTopic:
    topic_id: str
    title: str
    category: str
    summary: str
    body: str
    tags: List[str] = field(default_factory=list)
    updated_at: str = "2026-10-29"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "topic_id": self.topic_id,
            "title": self.title,
            "category": self.category,
            "summary": mask_secrets(self.summary),
            "body": mask_secrets(self.body),
            "tags": list(self.tags),
            "updated_at": self.updated_at,
        }
```

### 3.2 `ModelAdapterDocCatalog`
```python
class ModelAdapterDocCatalog:
    def get_topic(self, topic_id: str) -> Optional[ModelAdapterDocTopic]: ...
    def list_topics(self) -> List[ModelAdapterDocTopic]: ...
    def search(self, query: str, limit: int = 10) -> List[Dict[str, Any]]: ...
    def add_topic(self, topic: ModelAdapterDocTopic) -> None: ...
```

---

## 4. MCP Wire Tools

### 4.1 `aios_model_doc_get`
- **Parameters**: `topic_id: str`
- **PoR Requirement**: 0 tokens.
- **Returns**: `{status: "success", ok: true, data: Dict}` or `{status: "error", ok: false, error: str, message: str}`.

### 4.2 `aios_model_doc_search`
- **Parameters**: `query: str`, `limit: int = 10`
- **PoR Requirement**: 0 tokens.
- **Returns**: `{status: "success", ok: true, data: {query: str, count: int, results: List[Dict]}}`.

### 4.3 `aios_model_doc_list`
- **Parameters**: None.
- **PoR Requirement**: 0 tokens.
- **Returns**: `{status: "success", ok: true, data: {count: int, topics: List[Dict]}}`.

---

## 5. Usage Examples

### 5.1 Programmatic Python Invocation
```python
from aiosh_mcp.model_backend_adapters_doc import get_global_doc_catalog

catalog = get_global_doc_catalog()

# 1. Search for fallback & retry strategy
results = catalog.search("fallback retry cascade")
for r in results:
    print(f"[{r['score']}] {r['topic_id']}: {r['title']}")

# 2. Retrieve detailed topic specification
topic = catalog.get_topic("model.fallback")
print(topic.body)
```

### 5.2 FastMCP Tool Call (over stdio / MCP Client)
```json
// Tool Call: aios_model_doc_get
{
  "name": "aios_model_doc_get",
  "arguments": {
    "topic_id": "model.overview"
  }
}

// Tool Call: aios_model_doc_search
{
  "name": "aios_model_doc_search",
  "arguments": {
    "query": "tokens metering",
    "limit": 5
  }
}
```

---

## 6. Constraints & Known Limitations

1. **In-Memory Only**: The catalog is maintained entirely in process memory. It does not read from or write to disk or network sockets.
2. **Capacity Ceiling**: The catalog supports at most 256 topics (`MAX_TOPICS_LIMIT`). Attempting to add beyond this limit raises `MODDOC_ERR_CAPACITY_EXCEEDED`.
3. **Query Length Bounds**: Search queries are truncated to at most 128 characters (`MAX_DOC_QUERY_LEN`).
4. **Search Limit Clamping**: Search queries return at most 10 items (`MAX_DOC_SEARCH_RESULTS`).
5. **No Mutation over MCP**: MCP wire tools expose only read-only methods (`aios_model_doc_get`, `aios_model_doc_search`, `aios_model_doc_list`). Mutation is restricted to trusted process-local initialization.

---

## 7. Traceability & Task Evidence Links

- `T-03243`: Documentation Research — [`docs/tasks/evidence/T-03243-documentation-research.md`](file:///docs/tasks/evidence/T-03243-documentation-research.md)
- `T-03244`: Documentation Specification — [`docs/tasks/evidence/T-03244-documentation-specification.md`](file:///docs/tasks/evidence/T-03244-documentation-specification.md)
- `T-03245`: Documentation Scaffold — [`docs/tasks/evidence/T-03245-documentation-scaffold.md`](file:///docs/tasks/evidence/T-03245-documentation-scaffold.md)
- `T-03246`: Documentation Implementation — [`docs/tasks/evidence/T-03246-documentation-implementation.md`](file:///docs/tasks/evidence/T-03246-documentation-implementation.md)
- `T-03247`: Documentation Unit Test — [`docs/tasks/evidence/T-03247-documentation-unit-test.md`](file:///docs/tasks/evidence/T-03247-documentation-unit-test.md)
- `T-03248`: Documentation Integration — [`docs/tasks/evidence/T-03248-documentation-integration.md`](file:///docs/tasks/evidence/T-03248-documentation-integration.md)
- `T-03249`: Documentation Security Review — [`docs/tasks/evidence/T-03249-documentation-security-review.md`](file:///docs/tasks/evidence/T-03249-documentation-security-review.md)
- `T-03250`: Documentation Hardening — [`docs/tasks/evidence/T-03250-documentation-hardening.md`](file:///docs/tasks/evidence/T-03250-documentation-hardening.md)
- `T-03251`: Documentation Documentation — [`docs/tasks/evidence/T-03251-documentation-documentation.md`](file:///docs/tasks/evidence/T-03251-documentation-documentation.md)
