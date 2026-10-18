"""MCP Server Core Documentation Subsystem (MCPDOC-INV1..MCPDOC-INV5).

Provides self-contained reference documentation, topic search, and
schema discovery for AI Control Plane operators and autonomous agents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional

MAX_MCP_DOC_QUERY_LEN = 128
MAX_MCP_DOC_SEARCH_RESULTS = 10

MCPDOC_ERR_NOT_FOUND = "MCPDOC_ERR_NOT_FOUND"
MCPDOC_ERR_INVALID_ID = "MCPDOC_ERR_INVALID_ID"
MCPDOC_ERR_QUERY_BOUNDS = "MCPDOC_ERR_QUERY_BOUNDS"

BIDI_AND_INVISIBLE_CODEPOINTS = {
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x2066, 0x2067, 0x2068, 0x2069,
    0xFEFF,
}

TOPIC_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")


def sanitize_doc_query(s: str) -> str:
    """Strips control codes, invisible unicode codepoints, and clamps query length."""
    if not s:
        return ""
    filtered = []
    for c in s:
        cp = ord(c)
        if cp < 32 or (127 <= cp <= 159) or cp in BIDI_AND_INVISIBLE_CODEPOINTS:
            continue
        filtered.append(c)
    cleaned = "".join(filtered).strip()
    return cleaned[:MAX_MCP_DOC_QUERY_LEN]


def validate_topic_id(topic_id: str) -> None:
    """Validates topic ID against traversal tokens, NUL bytes, and syntax bounds (MCPDOC-INV3)."""
    trimmed = (topic_id or "").strip()
    if not trimmed:
        raise ValueError(f"{MCPDOC_ERR_INVALID_ID}: empty topic ID")
    if "\0" in trimmed or ".." in trimmed or "/" in trimmed or "\\" in trimmed:
        raise ValueError(f"{MCPDOC_ERR_INVALID_ID}: forbidden path or traversal character in topic ID")
    if not TOPIC_ID_PATTERN.match(trimmed):
        raise ValueError(f"{MCPDOC_ERR_INVALID_ID}: topic ID does not match valid syntax")


@dataclass(frozen=True)
class McpDocTopic:
    """Represents a documentation topic in the catalog."""
    topic_id: str
    title: str
    category: str
    summary: str
    content: str
    keywords: List[str] = field(default_factory=list)
    cross_references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "topic_id": self.topic_id,
            "title": self.title,
            "category": self.category,
            "summary": self.summary,
            "content": self.content,
            "keywords": self.keywords,
            "cross_references": self.cross_references,
        }


@dataclass(frozen=True)
class McpDocSearchResult:
    """Lightweight summary of search match."""
    topic_id: str
    title: str
    category: str
    summary: str
    score: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "topic_id": self.topic_id,
            "title": self.title,
            "category": self.category,
            "summary": self.summary,
            "score": self.score,
        }


class McpServerCoreDocCatalog:
    """In-memory documentation repository and keyword search index."""

    def __init__(self) -> None:
        self._topics: Dict[str, McpDocTopic] = {}

    def register(self, topic: McpDocTopic) -> None:
        validate_topic_id(topic.topic_id)
        self._topics[topic.topic_id] = topic

    def get(self, topic_id: str) -> McpDocTopic:
        validate_topic_id(topic_id)
        if topic_id not in self._topics:
            raise KeyError(f"{MCPDOC_ERR_NOT_FOUND}: topic '{topic_id}' not found")
        return self._topics[topic_id]

    def search(self, query: str) -> List[McpDocSearchResult]:
        sanitized = sanitize_doc_query(query).lower()
        if not sanitized:
            return []
        tokens = sanitized.split()
        results: List[McpDocSearchResult] = []
        for topic in self._topics.values():
            score = 0
            searchable_text = f"{topic.topic_id} {topic.title} {topic.summary} {' '.join(topic.keywords)}".lower()
            for token in tokens:
                if token in searchable_text:
                    score += 1
            if score > 0:
                results.append(
                    McpDocSearchResult(
                        topic_id=topic.topic_id,
                        title=topic.title,
                        category=topic.category,
                        summary=topic.summary,
                        score=score,
                    )
                )
        results.sort(key=lambda r: r.score, reverse=True)
        return results[:MAX_MCP_DOC_SEARCH_RESULTS]

    def list_topics(self) -> List[str]:
        return sorted(list(self._topics.keys()))


def build_default_doc_catalog() -> McpServerCoreDocCatalog:
    """Builds and populates the default documentation catalog with canonical topics."""
    catalog = McpServerCoreDocCatalog()

    catalog.register(
        McpDocTopic(
            topic_id="core.overview",
            title="MCP Server Core Overview",
            category="architecture",
            summary="Architecture and role of the AI Control Plane MCP Server Core (ADR-0035).",
            content=(
                "# MCP Server Core Overview\n\n"
                "The Model Context Protocol (MCP) server core operates as Pillar C's spine "
                "within AIOS. It serves as the unified tool-call interface for autonomous "
                "agents and operators, communicating over stdio and FastMCP."
            ),
            keywords=["overview", "architecture", "fastmcp", "adr-0035", "control plane", "spine"],
            cross_references=["core.api", "core.config", "core.policy"],
        )
    )

    catalog.register(
        McpDocTopic(
            topic_id="core.api",
            title="MCP Server Core Wire API",
            category="api",
            summary="JSON-RPC 2.0 framing, wire protocol routing, and tool dispatch.",
            content=(
                "# MCP Server Core Wire API\n\n"
                "Handles wire-level JSON-RPC 2.0 framing, method routing, and direct tool dispatch. "
                "Exposes `aios_mcp_api_ping` and `aios_mcp_api_jsonrpc` with strict 1 MiB payload bounds."
            ),
            keywords=["api", "jsonrpc", "wire", "dispatch", "ping", "initialize"],
            cross_references=["core.overview", "core.policy"],
        )
    )

    catalog.register(
        McpDocTopic(
            topic_id="core.config",
            title="MCP Server Core Configuration",
            category="configuration",
            summary="Resolution hierarchy, validation invariants, and parameter bounds.",
            content=(
                "# MCP Server Core Configuration\n\n"
                "Manages hierarchical resolution: CLI arguments > Environment variables > "
                "Config file > Built-in secure defaults. Enforces traversal rejection and size ceilings."
            ),
            keywords=["config", "configuration", "hierarchy", "environment", "store_path"],
            cross_references=["core.overview"],
        )
    )

    catalog.register(
        McpDocTopic(
            topic_id="core.tests",
            title="MCP Server Core Automated Test Runner",
            category="testing",
            summary="On-demand internal diagnostics and multi-layer health verification.",
            content=(
                "# MCP Server Core Automated Test Runner\n\n"
                "Exposes `aios_mcp_test_run` across diagnostic categories: data_model, api, "
                "service, config, and security (verifying PoR Invariant I-2)."
            ),
            keywords=["tests", "testing", "diagnostics", "suite", "runner"],
            cross_references=["core.policy", "core.observability"],
        )
    )

    catalog.register(
        McpDocTopic(
            topic_id="core.policy",
            title="MCP Server Core Security Policy",
            category="security",
            summary="Policy Enforcement Point (PEP) gating and Proof-of-Restraint Invariant I-2.",
            content=(
                "# MCP Server Core Security Policy\n\n"
                "Enforces declarative authorization and Zero Escalation (PoR Invariant I-2). "
                "Exposes `aios_mcp_policy_evaluate` and `aios_mcp_policy_status`."
            ),
            keywords=["policy", "security", "pep", "authorization", "por", "invariant i-2"],
            cross_references=["core.overview", "core.api"],
        )
    )

    catalog.register(
        McpDocTopic(
            topic_id="core.observability",
            title="MCP Server Core Observability",
            category="observability",
            summary="Real-time health telemetry, request throughput, and latency percentiles.",
            content=(
                "# MCP Server Core Observability\n\n"
                "Exposes `aios_mcp_observability_snapshot` for runtime operational status, "
                "enforcing counter invariants and zero-division protection."
            ),
            keywords=["observability", "metrics", "telemetry", "health", "latency"],
            cross_references=["core.overview", "core.tests"],
        )
    )

    catalog.register(
        McpDocTopic(
            topic_id="core.doc",
            title="MCP Server Core Documentation Subsystem",
            category="documentation",
            summary="Self-contained reference repository and topic search index.",
            content=(
                "# MCP Server Core Documentation Subsystem\n\n"
                "Provides self-documentation, keyword search, and schema discovery. "
                "Guarantees pure read-only execution, traversal immunity, and sanitization."
            ),
            keywords=["doc", "documentation", "lookup", "search", "catalog", "help"],
            cross_references=["core.overview", "core.api", "core.policy"],
        )
    )

    return catalog


_GLOBAL_DOC_CATALOG = build_default_doc_catalog()


def get_doc_catalog() -> McpServerCoreDocCatalog:
    return _GLOBAL_DOC_CATALOG


def register_mcp_doc_tools(mcp_app: Any) -> None:
    """Register MCP Server Core Documentation tools with FastMCP (T-03148)."""
    @mcp_app.tool()
    def aios_mcp_doc_lookup(topic_id: Optional[str] = None, query: Optional[str] = None) -> dict:
        """Look up reference documentation or search topics across the AI Control Plane MCP Server Core (ADR-0035)."""
        try:
            if topic_id:
                topic = _GLOBAL_DOC_CATALOG.get(topic_id)
                return {"ok": True, "topic": topic.to_dict()}
            elif query:
                results = _GLOBAL_DOC_CATALOG.search(query)
                return {"ok": True, "results": [r.to_dict() for r in results]}
            else:
                return {"ok": True, "topics": _GLOBAL_DOC_CATALOG.list_topics()}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


