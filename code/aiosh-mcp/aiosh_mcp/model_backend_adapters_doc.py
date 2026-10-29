"""AI Control Plane Model Backend Adapters Documentation Subsystem (T-03250 hardened).

Provides reference topic definitions, topic catalog, keyword search, and schema discovery in compliance with SPEC-MODEL-BACKEND-ADAPTERS-DOCUMENTATION and PoR Invariant I-2.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aiosh_mcp.model_backend_adapters_doc")

MAX_DOC_QUERY_LEN = 128
MAX_DOC_SEARCH_RESULTS = 10
MAX_TOPICS_LIMIT = 256
MAX_TOPIC_BODY_BYTES = 64 * 1024  # 64 KiB

MODDOC_ERR_NOT_FOUND = "MODDOC_ERR_NOT_FOUND"
MODDOC_ERR_INVALID_ID = "MODDOC_ERR_INVALID_ID"
MODDOC_ERR_QUERY_BOUNDS = "MODDOC_ERR_QUERY_BOUNDS"
MODDOC_ERR_INTERNAL = "MODDOC_ERR_INTERNAL"
MODDOC_ERR_CAPACITY_EXCEEDED = "MODDOC_ERR_CAPACITY_EXCEEDED"

BIDI_AND_INVISIBLE_CODEPOINTS = {
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x2066, 0x2067, 0x2068, 0x2069,
    0xFEFF,
}

TOPIC_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")
SECRET_PATTERN = re.compile(r"(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{20,}|Bearer\s+[a-zA-Z0-9_\-\.]{20,})", re.IGNORECASE)


def mask_secrets(text: str) -> str:
    """Masks API keys, tokens, and authorization credentials in documentation text."""
    if not text:
        return ""
    return SECRET_PATTERN.sub("[REDACTED_SECRET]", text)


def sanitize_doc_query(s: str) -> str:
    """Strips control codes, invisible unicode codepoints, normalizes NFKC, and clamps query length."""
    if not s:
        return ""
    normalized = unicodedata.normalize("NFKC", str(s))
    filtered = []
    for c in normalized:
        cp = ord(c)
        if cp < 32 or (127 <= cp <= 159) or cp in BIDI_AND_INVISIBLE_CODEPOINTS:
            continue
        filtered.append(c)
    cleaned = "".join(filtered).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned[:MAX_DOC_QUERY_LEN]


def validate_topic_id(topic_id: str) -> None:
    """Validates topic ID against traversal tokens, NUL bytes, and syntax bounds (MODDOC-INV3)."""
    trimmed = unicodedata.normalize("NFKC", (topic_id or "").strip())
    if not trimmed:
        raise ValueError(f"{MODDOC_ERR_INVALID_ID}: empty topic ID")
    if "\0" in trimmed or ".." in trimmed or "/" in trimmed or "\\" in trimmed:
        raise ValueError(f"{MODDOC_ERR_INVALID_ID}: forbidden path or traversal character in topic ID")
    if not TOPIC_ID_PATTERN.match(trimmed):
        raise ValueError(f"{MODDOC_ERR_INVALID_ID}: topic ID does not match valid syntax")


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


class ModelAdapterDocCatalog:
    """In-memory documentation catalog and search engine for model backend adapters."""

    def __init__(self) -> None:
        self._topics: Dict[str, ModelAdapterDocTopic] = {}
        self._initialize_default_topics()

    def _initialize_default_topics(self) -> None:
        defaults = [
            ModelAdapterDocTopic(
                topic_id="model.overview",
                title="Model Backend Adapters Architecture Overview",
                category="architecture",
                summary="AI Control Plane model adapter architecture, multi-provider routing, failover cascades, and token metering.",
                body=(
                    "The AIOS Model Backend Adapters provide a unified, pluggable interface between AIOS "
                    "agent workflows and LLM providers. Features include deterministic routing, policy gates, "
                    "automated failover cascades, token accounting, and Proof-of-Restraint token budgeting."
                ),
                tags=["overview", "architecture", "routing", "failover", "tokens"],
            ),
            ModelAdapterDocTopic(
                topic_id="model.providers",
                title="Supported LLM Model Providers and Configuration",
                category="providers",
                summary="Configuration specifications for OpenAI, Anthropic, Ollama, and Mock providers.",
                body=(
                    "Supported backend adapters include OpenAI, Anthropic, Ollama (local LLM), and Mock testing backends. "
                    "Credentials are held strictly within OS keyrings or environment variables and never logged or serialized "
                    "in MCP responses. Backend selection is governed by capability descriptors and cost envelopes."
                ),
                tags=["providers", "openai", "anthropic", "ollama", "mock", "credentials"],
            ),
            ModelAdapterDocTopic(
                topic_id="model.fallback",
                title="Automated Failover and Cascade Strategy",
                category="resilience",
                summary="Transient error detection, exponential backoff, circuit breaking, and secondary backend failover.",
                body=(
                    "When a backend encounters HTTP 429 (rate limit), 5xx, or network timeouts, the cascade engine "
                    "evaluates retry budgets before falling back to secondary providers. Circuit breakers isolate faulty "
                    "endpoints to avoid latency pileup."
                ),
                tags=["fallback", "cascade", "circuit-breaker", "resilience", "retry"],
            ),
            ModelAdapterDocTopic(
                topic_id="model.security",
                title="Security Policies, Prompt Invariant Guards, and Redaction",
                category="security",
                summary="Egress filtering, prompt injection guards, secret masking, and immutable audit trails.",
                body=(
                    "All prompts and completions are routed through security inspection filters. Invariants prohibit "
                    "credential leakage, unescaped raw control codes, and unauthorized token consumption. Consequential "
                    "invocations generate immutable audit events."
                ),
                tags=["security", "audit", "policy", "redaction", "prompt-guard"],
            ),
            ModelAdapterDocTopic(
                topic_id="model.observability",
                title="Telemetry, Metrics, and Latency Observability",
                category="observability",
                summary="Token consumption metering, latency histograms, error telemetry, and Prometheus export.",
                body=(
                    "The model adapter telemetry subsystem records request durations, prompt/completion token ratios, "
                    "cache hit rates, and error frequencies. Real-time metrics can be inspected via FastMCP tools and "
                    "dumped as structured telemetry snapshots."
                ),
                tags=["observability", "metrics", "telemetry", "latency", "tokens"],
            ),
        ]
        for t in defaults:
            self._topics[t.topic_id] = t

    def add_topic(self, topic: ModelAdapterDocTopic) -> None:
        """Adds a topic with capacity and size boundary checks."""
        validate_topic_id(topic.topic_id)
        if len(self._topics) >= MAX_TOPICS_LIMIT and topic.topic_id not in self._topics:
            raise ValueError(f"{MODDOC_ERR_CAPACITY_EXCEEDED}: catalog topic limit {MAX_TOPICS_LIMIT} reached")
        if len(topic.body.encode("utf-8")) > MAX_TOPIC_BODY_BYTES:
            raise ValueError(f"{MODDOC_ERR_QUERY_BOUNDS}: topic body exceeds maximum allowed size of {MAX_TOPIC_BODY_BYTES} bytes")
        self._topics[topic.topic_id] = topic

    def get_topic(self, topic_id: str) -> Optional[ModelAdapterDocTopic]:
        """Look up documentation topic by ID with syntax and traversal validation."""
        validate_topic_id(topic_id)
        return self._topics.get(topic_id)

    def list_topics(self) -> List[ModelAdapterDocTopic]:
        """Return all catalog topics sorted alphabetically by topic_id."""
        return sorted(self._topics.values(), key=lambda t: t.topic_id)

    def search(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Keyword search over topic title, tags, summary, and body with relevance scoring."""
        cleaned = sanitize_doc_query(query)
        if not cleaned:
            return []

        bounded_limit = max(1, min(limit, MAX_DOC_SEARCH_RESULTS))
        query_terms = [t.lower() for t in cleaned.split() if t]
        if not query_terms:
            return []

        scored_results = []
        for topic in self._topics.values():
            score = 0.0
            tid_lower = topic.topic_id.lower()
            title_lower = topic.title.lower()
            summary_lower = topic.summary.lower()
            body_lower = topic.body.lower()
            tags_lower = [tag.lower() for tag in topic.tags]

            for term in query_terms:
                if term in tid_lower:
                    score += 10.0
                if term in title_lower:
                    score += 5.0
                if any(term in tag for tag in tags_lower):
                    score += 3.0
                if term in summary_lower:
                    score += 2.0
                if term in body_lower:
                    score += 1.0

            if score > 0.0:
                scored_results.append({
                    "topic_id": topic.topic_id,
                    "title": topic.title,
                    "category": topic.category,
                    "summary": mask_secrets(topic.summary),
                    "score": round(score, 2),
                })

        scored_results.sort(key=lambda r: (-r["score"], r["topic_id"]))
        return scored_results[:bounded_limit]


_GLOBAL_DOC_CATALOG = ModelAdapterDocCatalog()


def get_global_doc_catalog() -> ModelAdapterDocCatalog:
    """Returns the process-wide ModelAdapterDocCatalog singleton."""
    return _GLOBAL_DOC_CATALOG


def register_model_doc_tools(mcp_server: Any) -> None:
    """Registers Model Backend Adapters Documentation MCP tools (T-03248 / T-03250)."""

    @mcp_server.tool()
    def aios_model_doc_get(topic_id: str) -> dict:
        """Retrieve detailed documentation topic by its identifier (pure read-only, 0 tokens)."""
        try:
            topic = get_global_doc_catalog().get_topic(topic_id)
            if topic is None:
                return {
                    "status": "error",
                    "ok": False,
                    "error": MODDOC_ERR_NOT_FOUND,
                    "message": f"Topic not found: {topic_id}",
                }
            return {
                "status": "success",
                "ok": True,
                "data": topic.to_dict(),
            }
        except ValueError as ve:
            return {
                "status": "error",
                "ok": False,
                "error": MODDOC_ERR_INVALID_ID,
                "message": str(ve),
            }
        except Exception as e:
            logger.error(f"Unexpected error in aios_model_doc_get: {e}")
            return {
                "status": "error",
                "ok": False,
                "error": MODDOC_ERR_INTERNAL,
                "message": "Internal error retrieving documentation topic",
            }

    @mcp_server.tool()
    def aios_model_doc_search(query: str, limit: int = 10) -> dict:
        """Search model backend adapter documentation topics by keywords (pure read-only, 0 tokens)."""
        try:
            results = get_global_doc_catalog().search(query, limit=limit)
            return {
                "status": "success",
                "ok": True,
                "data": {
                    "query": sanitize_doc_query(query),
                    "count": len(results),
                    "results": results,
                },
            }
        except Exception as e:
            logger.error(f"Unexpected error in aios_model_doc_search: {e}")
            return {
                "status": "error",
                "ok": False,
                "error": MODDOC_ERR_INTERNAL,
                "message": "Internal error searching documentation topics",
            }

    @mcp_server.tool()
    def aios_model_doc_list() -> dict:
        """List all available model backend adapter documentation topics (pure read-only, 0 tokens)."""
        try:
            topics = get_global_doc_catalog().list_topics()
            return {
                "status": "success",
                "ok": True,
                "data": {
                    "count": len(topics),
                    "topics": [t.to_dict() for t in topics],
                },
            }
        except Exception as e:
            logger.error(f"Unexpected error in aios_model_doc_list: {e}")
            return {
                "status": "error",
                "ok": False,
                "error": MODDOC_ERR_INTERNAL,
                "message": "Internal error listing documentation topics",
            }
