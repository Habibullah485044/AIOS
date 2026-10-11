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


def sanitize_doc_query(s: str) -> str:
    """Strips ASCII/Unicode control characters and trims query string."""
    return "".join(c for c in s if not (ord(c) < 32 or (127 <= ord(c) <= 159))).strip()


def validate_topic_id(topic_id: str) -> None:
    """Validates topic identifier against path traversal and forbidden characters."""
    trimmed = (topic_id or "").strip()
    if not trimmed:
        raise ValueError(f"{COMPLYDOC_ERR_NOT_FOUND}: empty topic ID")
    if ".." in trimmed or "/" in trimmed or "\\" in trimmed or "\0" in trimmed:
        raise ValueError(f"{COMPLYDOC_ERR_NOT_FOUND}: invalid characters in topic ID")
    if any(ord(c) < 32 or (127 <= ord(c) <= 159) for c in trimmed):
        raise ValueError(f"{COMPLYDOC_ERR_NOT_FOUND}: control characters in topic ID")


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


def get_canonical_compliance_topics() -> list[ComplianceDocTopic]:
    """Returns canonical reference topics for Compliance Mapping."""
    return [
        ComplianceDocTopic(
            id="compliance.arch.overview",
            title="Compliance Mapping Architecture & Target Bindings",
            category=ComplianceDocCategory.ARCHITECTURE,
            summary="Comprehensive architecture of AIOS compliance mapping connecting regulatory controls to concrete execution substrates.",
            sections=[
                ComplianceDocSection(
                    title="Substrate Target Types",
                    content="Supported targets include PEP gates, audit rings, sandbox profiles, capability grants, and system update verifiers.",
                ),
                ComplianceDocSection(
                    title="Data Model",
                    content="Compliance mappings bind unique mapping IDs, control IDs, regulatory frameworks, substrate targets, lifecycle statuses, and MITRE threat IDs.",
                ),
            ],
            related_topics=[
                "compliance.frameworks.taxonomy",
                "compliance.lifecycle.states",
            ],
        ),
        ComplianceDocTopic(
            id="compliance.frameworks.taxonomy",
            title="Supported Regulatory Frameworks Taxonomy",
            category=ComplianceDocCategory.FRAMEWORKS,
            summary="Taxonomy of supported security and compliance frameworks in AIOS.",
            sections=[
                ComplianceDocSection(
                    title="NIST SP 800-53 Rev 5",
                    content="Federal information system security controls catalog covering AC, AU, SI, and SC families.",
                ),
                ComplianceDocSection(
                    title="ISO/IEC 27001:2022",
                    content="Information security management systems controls in Annex A.",
                ),
                ComplianceDocSection(
                    title="SOC 2 Type II",
                    content="Trust Services Criteria covering security, availability, and confidentiality.",
                ),
                ComplianceDocSection(
                    title="CIS Controls v8",
                    content="Prioritized set of 18 critical security actions.",
                ),
            ],
            related_topics=[
                "compliance.arch.overview",
                "compliance.policy.gates",
            ],
        ),
        ComplianceDocTopic(
            id="compliance.lifecycle.states",
            title="Compliance Lifecycle States & Transition Rules",
            category=ComplianceDocCategory.LIFECYCLE,
            summary="Formal state machine rules governing mapping status transitions from non-compliant to verified compliant.",
            sections=[
                ComplianceDocSection(
                    title="Status States",
                    content="Valid lifecycle statuses are 'non_compliant', 'partially_compliant', 'compliant', and 'not_applicable'.",
                ),
                ComplianceDocSection(
                    title="Transition Invariants",
                    content="Transitions require valid cryptographic rationale and maintain monotonically non-decreasing evidence validation.",
                ),
            ],
            related_topics=[
                "compliance.service.api",
                "compliance.policy.gates",
            ],
        ),
        ComplianceDocTopic(
            id="compliance.service.api",
            title="Compliance Service Core Operations & Persistence",
            category=ComplianceDocCategory.SERVICE,
            summary="API reference for the in-memory and persistent compliance service managing mapping snapshots.",
            sections=[
                ComplianceDocSection(
                    title="Snapshot Operations",
                    content="Provides register, update status, assess framework compliance ratio, and verify PEP coverage.",
                ),
                ComplianceDocSection(
                    title="Atomic Persistence",
                    content="Backs data with 1 MiB bounded JSON stores utilizing atomic rename and deterministic sorting.",
                ),
            ],
            related_topics=[
                "compliance.arch.overview",
                "compliance.observability.telemetry",
            ],
        ),
        ComplianceDocTopic(
            id="compliance.policy.gates",
            title="Compliance Policy Enforcement & Security Gates",
            category=ComplianceDocCategory.POLICY,
            summary="Security policy evaluating framework whitelisting, PEP gate verification, and compliance thresholds.",
            sections=[
                ComplianceDocSection(
                    title="Enforcement Modes",
                    content="Supports 'audit_only' for permissive telemetry logging and 'enforce' for fail-closed execution blocking.",
                ),
                ComplianceDocSection(
                    title="Gate Evaluation",
                    content="Evaluates mandatory frameworks, minimum compliance ratios, and threat ID coverage prior to privileged actions.",
                ),
            ],
            related_topics=[
                "compliance.lifecycle.states",
                "compliance.recovery.backup",
            ],
        ),
        ComplianceDocTopic(
            id="compliance.observability.telemetry",
            title="Compliance Observability, Metrics & Telemetry",
            category=ComplianceDocCategory.OBSERVABILITY,
            summary="Telemetry aggregation and health monitoring for regulatory mappings across active workloads.",
            sections=[
                ComplianceDocSection(
                    title="Observability Metrics",
                    content="Calculates framework status distributions, overall compliance ratios, capacity utilization, and policy modes.",
                ),
                ComplianceDocSection(
                    title="Audit Correlation",
                    content="Integrates with SHA-256 hash-chained audit rings to guarantee non-repudiation of compliance assessments.",
                ),
            ],
            related_topics=[
                "compliance.service.api",
                "compliance.policy.gates",
            ],
        ),
        ComplianceDocTopic(
            id="compliance.recovery.backup",
            title="Compliance Store Recovery & Snapshot Backup",
            category=ComplianceDocCategory.RECOVERY,
            summary="Disaster recovery, integrity checking, and snapshot restoration procedures for compliance stores.",
            sections=[
                ComplianceDocSection(
                    title="Integrity Verification",
                    content="Validates schema versions, mapping count bounds (<= 1024), and UTF-8 encoding integrity.",
                ),
                ComplianceDocSection(
                    title="Recovery Procedures",
                    content="Defines atomic fallback to canonical seed baselines when corruption or IO failure is detected.",
                ),
            ],
            related_topics=[
                "compliance.service.api",
                "compliance.arch.overview",
            ],
        ),
    ]


class ComplianceDocRepository:
    def __init__(self, topics: list[ComplianceDocTopic] | None = None) -> None:
        self.topics = topics if topics is not None else get_canonical_compliance_topics()

    def list_topics(self) -> list[ComplianceDocTopic]:
        return list(self.topics)

    def get_topic(self, topic_id: str) -> ComplianceDocTopic:
        validate_topic_id(topic_id)
        target = topic_id.strip()
        for topic in self.topics:
            if topic.id == target:
                return topic
        raise ValueError(f"{COMPLYDOC_ERR_NOT_FOUND}: topic '{topic_id}' not found")

    def search(self, query: str) -> list[ComplianceDocSearchResult]:
        cleaned = sanitize_doc_query(query)
        if not cleaned or len(query.strip()) > MAX_COMPLIANCE_DOC_QUERY_LEN:
            raise ValueError(
                f"{COMPLYDOC_ERR_QUERY_BOUNDS}: query length must be between 1 and {MAX_COMPLIANCE_DOC_QUERY_LEN} chars"
            )

        query_lower = cleaned.lower()
        tokens = query_lower.split()
        if not tokens:
            raise ValueError(f"{COMPLYDOC_ERR_QUERY_BOUNDS}: search query contains no searchable tokens")

        results: list[ComplianceDocSearchResult] = []

        for topic in self.topics:
            score = 0
            best_snippet = ""

            # 1. Exact match on topic.id: +50 points
            if topic.id.lower() == query_lower:
                score += 50

            # 2. Match in topic.title: +25 points
            title_lower = topic.title.lower()
            for token in tokens:
                if token in title_lower:
                    score += 25

            # 3. Match in topic.summary: +15 points
            summary_lower = topic.summary.lower()
            for token in tokens:
                if token in summary_lower:
                    score += 15
                    if not best_snippet:
                        best_snippet = topic.summary

            # 4. Match in sections: title (+5), content (+2)
            for section in topic.sections:
                sec_title_lower = section.title.lower()
                sec_content_lower = section.content.lower()
                for token in tokens:
                    if token in sec_title_lower:
                        score += 5
                        if not best_snippet:
                            best_snippet = f"{section.title}: {section.content}"
                    if token in sec_content_lower:
                        score += 2
                        if not best_snippet:
                            best_snippet = section.content

            if score > 0:
                if not best_snippet:
                    snippet = topic.summary
                elif len(best_snippet) > MAX_COMPLIANCE_DOC_SNIPPET_LEN:
                    snippet = best_snippet[:MAX_COMPLIANCE_DOC_SNIPPET_LEN] + "..."
                else:
                    snippet = best_snippet

                results.append(
                    ComplianceDocSearchResult(
                        topic_id=topic.id,
                        title=topic.title,
                        category=topic.category,
                        score=score,
                        snippet=snippet,
                    )
                )

        # Sort descending by score, ascending by topic_id for determinism
        results.sort(key=lambda r: (-r.score, r.topic_id))
        return results[:MAX_COMPLIANCE_DOC_SEARCH_RESULTS]
