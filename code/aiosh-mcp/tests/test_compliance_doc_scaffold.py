"""Scaffold verification test for Compliance Mapping Documentation Subsystem (T-02945)."""

import pytest

from aiosh_mcp.compliance import execute
from aiosh_mcp.compliance_doc import (
    COMPLYDOC_ERR_NOT_FOUND,
    COMPLYDOC_ERR_QUERY_BOUNDS,
    MAX_COMPLIANCE_DOC_QUERY_LEN,
    MAX_COMPLIANCE_DOC_SEARCH_RESULTS,
    MAX_COMPLIANCE_DOC_SNIPPET_LEN,
    ComplianceDocCategory,
    ComplianceDocRepository,
    ComplianceDocSection,
    ComplianceDocTopic,
)


def test_compliance_doc_scaffold_constants_and_types() -> None:
    assert MAX_COMPLIANCE_DOC_QUERY_LEN == 128
    assert MAX_COMPLIANCE_DOC_SEARCH_RESULTS == 10
    assert MAX_COMPLIANCE_DOC_SNIPPET_LEN == 200

    assert COMPLYDOC_ERR_NOT_FOUND == "COMPLYDOC_ERR_NOT_FOUND"
    assert COMPLYDOC_ERR_QUERY_BOUNDS == "COMPLYDOC_ERR_QUERY_BOUNDS"

    assert ComplianceDocCategory.ARCHITECTURE.value == "architecture"
    assert ComplianceDocCategory.FRAMEWORKS.value == "frameworks"
    assert ComplianceDocCategory.LIFECYCLE.value == "lifecycle"
    assert ComplianceDocCategory.SERVICE.value == "service"
    assert ComplianceDocCategory.POLICY.value == "policy"
    assert ComplianceDocCategory.OBSERVABILITY.value == "observability"
    assert ComplianceDocCategory.RECOVERY.value == "recovery"

    sec = ComplianceDocSection(title="Overview", content="Content text")
    topic = ComplianceDocTopic(
        id="comply-arch",
        title="Compliance Architecture",
        category=ComplianceDocCategory.ARCHITECTURE,
        summary="Architecture summary",
        sections=[sec],
        related_topics=["comply-frameworks"],
    )
    md = topic.to_markdown()
    assert "# Compliance Architecture" in md
    assert "**Category**: `architecture`" in md
    assert "## Overview" in md


def test_compliance_doc_scaffold_loud_failure_stubs() -> None:
    repo = ComplianceDocRepository()
    assert repo.list_topics() == []

    with pytest.raises(NotImplementedError):
        repo.get_topic("comply-arch")

    with pytest.raises(NotImplementedError):
        repo.search("test")

    with pytest.raises(NotImplementedError):
        execute("doc-list")

    with pytest.raises(NotImplementedError):
        execute("doc-get", id="comply-arch")

    with pytest.raises(NotImplementedError):
        execute("doc-search")
