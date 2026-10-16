"""Incident Response Runbooks Documentation Subsystem (IRDOC1..IRDOC5).

Provides an offline, self-contained reference repository and search index for
Incident Response Runbooks, playbook schemas, execution state progression,
RustSec scanning tools, security policies, and observability metrics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

MAX_RUNBOOK_DOC_QUERY_LEN = 128
MAX_RUNBOOK_DOC_SEARCH_RESULTS = 10
MAX_RUNBOOK_DOC_SNIPPET_LEN = 200

IRDOC_ERR_NOT_FOUND = "IRDOC_ERR_NOT_FOUND"
IRDOC_ERR_QUERY_BOUNDS = "IRDOC_ERR_QUERY_BOUNDS"


BIDI_AND_INVISIBLE_CODEPOINTS = {
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x2066, 0x2067, 0x2068, 0x2069,
    0xFEFF,
}


def sanitize_doc_query(s: str) -> str:
    """Strips ASCII/Unicode control characters, bidi overrides, and trims query string."""
    filtered = []
    for c in s:
        cp = ord(c)
        if cp < 32 or (127 <= cp <= 159) or cp in BIDI_AND_INVISIBLE_CODEPOINTS:
            continue
        filtered.append(c)
    return "".join(filtered).strip()


def validate_topic_id(topic_id: str) -> None:
    """Validates topic identifier against path traversal, forbidden characters, and boundaries."""
    trimmed = (topic_id or "").strip()
    if not trimmed:
        raise ValueError(f"{IRDOC_ERR_NOT_FOUND}: empty topic ID")
    if ".." in trimmed or "/" in trimmed or "\\" in trimmed or "\0" in trimmed:
        raise ValueError(f"{IRDOC_ERR_NOT_FOUND}: invalid characters in topic ID")
    if trimmed.startswith(".") or trimmed.endswith(".") or trimmed.startswith("-") or trimmed.endswith("-"):
        raise ValueError(f"{IRDOC_ERR_NOT_FOUND}: invalid boundary characters in topic ID")
    for c in trimmed:
        if not (c.isalnum() or c in (".", "_", "-")):
            raise ValueError(f"{IRDOC_ERR_NOT_FOUND}: forbidden character '{c}' in topic ID")
        if ord(c) < 32 or (127 <= ord(c) <= 159):
            raise ValueError(f"{IRDOC_ERR_NOT_FOUND}: control characters in topic ID")


class RunbookDocCategory(str, Enum):
    ARCHITECTURE = "architecture"
    DATAMODEL = "datamodel"
    LIFECYCLE = "lifecycle"
    SECURITY_TOOLS = "security_tools"
    POLICY = "policy"
    OBSERVABILITY = "observability"
    RECOVERY = "recovery"


@dataclass
class RunbookDocSection:
    title: str
    content: str


@dataclass
class RunbookDocTopic:
    id: str
    title: str
    category: RunbookDocCategory
    summary: str
    sections: list[RunbookDocSection] = field(default_factory=list)
    related_topics: list[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        lines = [
            f"# {self.title}",
            "",
            f"**Category**: `{self.category.value}`",
            f"**ID**: `{self.id}`",
            "",
            self.summary,
            "",
        ]
        for sec in self.sections:
            lines.extend([f"## {sec.title}", "", sec.content, ""])
        if self.related_topics:
            lines.extend(["### Related Topics", ""])
            for rel in self.related_topics:
                lines.append(f"- `{rel}`")
            lines.append("")
        return "\n".join(lines)


@dataclass
class RunbookDocSearchResult:
    topic_id: str
    title: str
    category: RunbookDocCategory
    score: int
    snippet: str


class RunbookDocRepository:
    def __init__(self) -> None:
        self.topics: list[RunbookDocTopic] = []
        self._populate_canonical_topics()

    def list_topics(self) -> list[RunbookDocTopic]:
        return list(self.topics)

    def list_by_category(self, cat: RunbookDocCategory) -> list[RunbookDocTopic]:
        return [t for t in self.topics if t.category == cat]

    def get_topic(self, topic_id: str) -> RunbookDocTopic | None:
        try:
            validate_topic_id(topic_id)
        except ValueError:
            return None
        for t in self.topics:
            if t.id == topic_id:
                return t
        return None

    def search(
        self, query: str, category: RunbookDocCategory | None = None
    ) -> list[RunbookDocSearchResult]:
        sanitized = sanitize_doc_query(query)
        if not sanitized or len(sanitized) > MAX_RUNBOOK_DOC_QUERY_LEN:
            raise ValueError(f"{IRDOC_ERR_QUERY_BOUNDS}: invalid query length")

        tokens = [t.lower() for t in sanitized.split() if t]
        if not tokens:
            raise ValueError(f"{IRDOC_ERR_QUERY_BOUNDS}: empty tokens")

        results: list[RunbookDocSearchResult] = []
        for topic in self.topics:
            if category and topic.category != category:
                continue

            score = 0
            matched_snippet = ""
            title_lower = topic.title.lower()
            summary_lower = topic.summary.lower()

            for token in tokens:
                if token in title_lower:
                    score += 10
                if token in summary_lower:
                    score += 5
                    if not matched_snippet:
                        matched_snippet = topic.summary

            for sec in topic.sections:
                sec_title_lower = sec.title.lower()
                sec_content_lower = sec.content.lower()
                for token in tokens:
                    if token in sec_title_lower:
                        score += 3
                    if token in sec_content_lower:
                        score += 1
                        if not matched_snippet:
                            matched_snippet = sec.content

            if score > 0:
                if len(matched_snippet) > MAX_RUNBOOK_DOC_SNIPPET_LEN:
                    snippet = f"{matched_snippet[:MAX_RUNBOOK_DOC_SNIPPET_LEN]}..."
                elif not matched_snippet:
                    snippet = topic.summary
                else:
                    snippet = matched_snippet

                results.append(
                    RunbookDocSearchResult(
                        topic_id=topic.id,
                        title=topic.title,
                        category=topic.category,
                        score=score,
                        snippet=snippet,
                    )
                )

        results.sort(key=lambda x: x.score, reverse=True)
        return results[:MAX_RUNBOOK_DOC_SEARCH_RESULTS]

    def _populate_canonical_topics(self) -> None:
        self.topics = [
            RunbookDocTopic(
                id="runbook.arch.overview",
                title="Incident Response Runbooks Architecture",
                category=RunbookDocCategory.ARCHITECTURE,
                summary="Architectural overview of the AIOS Incident Response Runbooks subsystem, aligned with NIST SP 800-61 Rev. 2 and CISA Playbooks.",
                sections=[
                    RunbookDocSection(
                        title="Core Architecture",
                        content="Dual-substrate implementation coordinating between RustSec scanning engines and FastMCP execution services.",
                    ),
                    RunbookDocSection(
                        title="Security Governance",
                        content="Enforcing dual-gate dispatch: classifier rule-pack verification and PEP grant capability redemption before any destructive action.",
                    ),
                ],
                related_topics=["runbook.datamodel.specs", "runbook.policy.governance"],
            ),
            RunbookDocTopic(
                id="runbook.datamodel.specs",
                title="Incident Runbook Data Model Specifications",
                category=RunbookDocCategory.DATAMODEL,
                summary="Specifications of IncidentRunbookSpec, step parameters, targets, and canonical baseline catalog.",
                sections=[
                    RunbookDocSection(
                        title="Runbook Schemas",
                        content="Canonical playbooks RB-IR-MALWARE-01 and RB-IR-ACCESS-01 covering containment, eradication, and recovery.",
                    ),
                ],
                related_topics=["runbook.arch.overview", "runbook.lifecycle.execution"],
            ),
            RunbookDocTopic(
                id="runbook.lifecycle.execution",
                title="Runbook Execution Lifecycle & Session Advancement",
                category=RunbookDocCategory.LIFECYCLE,
                summary="State machine rules governing session start, step progression, confirmation gates, and abort semantics.",
                sections=[
                    RunbookDocSection(
                        title="Session Transitions",
                        content="States progress from ACTIVE to COMPLETED, FAILED, or ABORTED with mandatory operator confirmation for high-risk steps.",
                    ),
                ],
                related_topics=["runbook.policy.governance"],
            ),
            RunbookDocTopic(
                id="runbook.tools.scanning",
                title="RustSec Diagnostic Security Scanning Tools",
                category=RunbookDocCategory.SECURITY_TOOLS,
                summary="Comprehensive guide to aiosh scan subcommands: net (port scan), files (pattern hunting), and web (path probing).",
                sections=[
                    RunbookDocSection(
                        title="Target Validation & Resource Clamping",
                        content="Strict whitelist target validation, path traversal prohibition, and bounded ports, depth, and file size limits.",
                    ),
                ],
                related_topics=["runbook.arch.overview"],
            ),
            RunbookDocTopic(
                id="runbook.config.precedence",
                title="Runbook Configuration Precedence Ladder",
                category=RunbookDocCategory.ARCHITECTURE,
                summary="4-level configuration hierarchy: Explicit CLI/MCP args > Environment Variables > Config File > Built-in Defaults.",
                sections=[
                    RunbookDocSection(
                        title="Configuration Resolution",
                        content="Resolves aiosh.runbook.toml with strict 64 KiB size caps and bounds validation.",
                    ),
                ],
                related_topics=["runbook.policy.governance"],
            ),
            RunbookDocTopic(
                id="runbook.policy.governance",
                title="Runbook Security Policy & Gate Enforcement",
                category=RunbookDocCategory.POLICY,
                summary="Policy evaluation regimes (Enforcing, Permissive, Disabled), confirmation token requirements, and ADR-0035 honest audit rows.",
                sections=[
                    RunbookDocSection(
                        title="Enforcement Regimes",
                        content="Fail-closed confirmation gating on containment actions; honest audit row required on permissive bypass.",
                    ),
                ],
                related_topics=["runbook.observability.telemetry"],
            ),
            RunbookDocTopic(
                id="runbook.observability.telemetry",
                title="Incident Response Telemetry & Observability",
                category=RunbookDocCategory.OBSERVABILITY,
                summary="Real-time metrics aggregation, session utilization, healthy status monitoring, and ADR-0035 §AF-2 compliance.",
                sections=[
                    RunbookDocSection(
                        title="Observability Result Envelope",
                        content="Explicit error envelopes preventing silent failure and logging honest audit rows on capacity saturation.",
                    ),
                ],
                related_topics=["runbook.policy.governance"],
            ),
        ]
