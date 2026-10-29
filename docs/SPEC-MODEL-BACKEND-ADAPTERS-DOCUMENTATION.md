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
            "summary": self.summary,
            "body": self.body,
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
```

---

## 4. MCP Wire Tools

### 4.1 `aios_model_doc_get`
- **Parameters**: `topic_id: str`
- **PoR Requirement**: 0 tokens.
- **Returns**: `{status: "success", ok: true, topic: Dict}` or `{status: "error", ok: false, error: str}`.

### 4.2 `aios_model_doc_search`
- **Parameters**: `query: str`, `limit: int = 10`
- **PoR Requirement**: 0 tokens.
- **Returns**: `{status: "success", ok: true, count: int, results: List[Dict]}`.
