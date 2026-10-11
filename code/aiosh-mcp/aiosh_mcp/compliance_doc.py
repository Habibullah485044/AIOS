"""Compliance Mapping Documentation Subsystem (COMPLYDOC1..COMPLYDOC5).

Provides an offline, self-contained reference repository and search index for
Compliance Mapping, regulatory frameworks taxonomy, lifecycle state rules,
security policy gates, telemetry schemas, and recovery protocols.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

MAX_COMPLIANCE_DOC_QUERY_LEN = 128
MAX_COMPLIANCE_DOC_SEARCH_RESULTS = 10
MAX_COMPLIANCE_DOC_SNIPPET_LEN = 200

COMPLYDOC_ERR_NOT_FOUND = "COMPLYDOC_ERR_NOT_FOUND"
COMPLYDOC_ERR_QUERY_BOUNDS = "COMPLYDOC_ERR_QUERY_BOUNDS"


class ComplianceDocCategory(str, Enum):
    ARCHITECTURE = "architecture"
    FRAMEWORKS = "frameworks"
    LIFECYCLE = "lifecycle"
    SERVICE = "service"
    POLICY = "policy"
    OBSERVABILITY = "observability"
    RECOVERY = "recovery"


@dataclass
class ComplianceDocSection:
    title: str
    content: str


@dataclass
class ComplianceDocTopic:
    id: str
    title: str
    category: ComplianceDocCategory
    summary: str
    sections: list[ComplianceDocSection] = field(default_factory=list)
    related_topics: list[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        md = f"# {self.title}\n\n**Category**: `{self.category.value}`\n**ID**: `{self.id}`\n\n{self.summary}\n\n"
        for sec in self.sections:
            md += f"## {sec.title}\n\n{sec.content}\n\n"
        if self.related_topics:
            md += "### Related Topics\n\n"
            for rel in self.related_topics:
                md += f"- `{rel}`\n"
        return md


@dataclass
class ComplianceDocSearchResult:
    topic_id: str
    title: str
    category: ComplianceDocCategory
    score: int
    snippet: str


class ComplianceDocRepository:
    def __init__(self, topics: list[ComplianceDocTopic] | None = None) -> None:
        self.topics = topics or []

    def list_topics(self) -> list[ComplianceDocTopic]:
        return list(self.topics)

    def get_topic(self, topic_id: str) -> ComplianceDocTopic:
        # Scaffold stub (T-02945): fails loudly
        raise NotImplementedError("ComplianceDocRepository.get_topic scaffolded for T-02945")

    def search(self, query: str) -> list[ComplianceDocSearchResult]:
        # Scaffold stub (T-02945): fails loudly
        raise NotImplementedError("ComplianceDocRepository.search scaffolded for T-02945")
