"""Unit tests for Compliance Mapping Documentation Subsystem (T-02947)."""

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
    sanitize_doc_query,
    validate_topic_id,
)


def test_canonical_topics_enumeration() -> None:
    repo = ComplianceDocRepository()
    topics = repo.list_topics()
    assert len(topics) == 7

    ids = [t.id for t in topics]
    assert "compliance.arch.overview" in ids
    assert "compliance.frameworks.taxonomy" in ids
    assert "compliance.lifecycle.states" in ids
    assert "compliance.service.api" in ids
    assert "compliance.policy.gates" in ids
    assert "compliance.observability.telemetry" in ids
    assert "compliance.recovery.backup" in ids


def test_get_topic_positive() -> None:
    repo = ComplianceDocRepository()

    arch = repo.get_topic("compliance.arch.overview")
    assert arch.category == ComplianceDocCategory.ARCHITECTURE
    assert "Architecture" in arch.title
    assert len(arch.sections) > 0
    assert "compliance.frameworks.taxonomy" in arch.related_topics

    fw = repo.get_topic("compliance.frameworks.taxonomy")
    assert fw.category == ComplianceDocCategory.FRAMEWORKS
    assert any("NIST SP 800-53" in s.title for s in fw.sections)


def test_get_topic_negative_and_validation() -> None:
    repo = ComplianceDocRepository()

    with pytest.raises(ValueError) as exc:
        repo.get_topic("compliance.nonexistent")
    assert COMPLYDOC_ERR_NOT_FOUND in str(exc.value)

    with pytest.raises(ValueError) as exc:
        repo.get_topic("")
    assert COMPLYDOC_ERR_NOT_FOUND in str(exc.value)

    with pytest.raises(ValueError) as exc:
        repo.get_topic("../etc/passwd")
    assert COMPLYDOC_ERR_NOT_FOUND in str(exc.value)

    with pytest.raises(ValueError) as exc:
        repo.get_topic("compliance/arch/overview")
    assert COMPLYDOC_ERR_NOT_FOUND in str(exc.value)

    with pytest.raises(ValueError) as exc:
        repo.get_topic("compliance\x00arch")
    assert COMPLYDOC_ERR_NOT_FOUND in str(exc.value)

    validate_topic_id("valid.id")
    with pytest.raises(ValueError):
        validate_topic_id("..")
    with pytest.raises(ValueError):
        validate_topic_id("")


def test_query_sanitization() -> None:
    assert sanitize_doc_query("  clean query  ") == "clean query"
    assert sanitize_doc_query("hello\x00world\x1b[31m") == "helloworld[31m"


def test_search_relevance_and_scoring() -> None:
    repo = ComplianceDocRepository()

    # Exact ID match
    hits = repo.search("compliance.frameworks.taxonomy")
    assert len(hits) > 0
    assert hits[0].topic_id == "compliance.frameworks.taxonomy"
    assert hits[0].score >= 50

    # Title match
    hits = repo.search("Architecture")
    assert len(hits) > 0
    assert hits[0].topic_id == "compliance.arch.overview"
    assert hits[0].score >= 25

    # Summary match
    hits = repo.search("telemetry")
    assert len(hits) > 0
    assert hits[0].topic_id == "compliance.observability.telemetry"

    # Section match
    hits = repo.search("NIST")
    assert len(hits) > 0
    assert hits[0].topic_id == "compliance.frameworks.taxonomy"


def test_search_bounds_and_errors() -> None:
    repo = ComplianceDocRepository()

    with pytest.raises(ValueError) as exc:
        repo.search("")
    assert COMPLYDOC_ERR_QUERY_BOUNDS in str(exc.value)

    with pytest.raises(ValueError) as exc:
        repo.search("     ")
    assert COMPLYDOC_ERR_QUERY_BOUNDS in str(exc.value)

    long_query = "a" * (MAX_COMPLIANCE_DOC_QUERY_LEN + 1)
    with pytest.raises(ValueError) as exc:
        repo.search(long_query)
    assert COMPLYDOC_ERR_QUERY_BOUNDS in str(exc.value)

    max_query = "a" * MAX_COMPLIANCE_DOC_QUERY_LEN
    res = repo.search(max_query)
    assert isinstance(res, list)


def test_mcp_surface_doc_actions() -> None:
    # doc-list
    res_list = execute("doc-list")
    assert res_list["ok"] is True
    assert res_list["count"] == 7
    assert len(res_list["topics"]) == 7

    # doc-get positive
    res_get = execute("doc-get", id="compliance.arch.overview")
    assert res_get["ok"] is True
    assert res_get["topic"]["id"] == "compliance.arch.overview"
    assert "markdown" in res_get["topic"]

    # doc-get negative
    with pytest.raises(ValueError):
        execute("doc-get", id="nonexistent")

    with pytest.raises(ValueError):
        execute("doc-get", id="")

    # doc-search positive
    res_search = execute("doc-search", query="Architecture")
    assert res_search["ok"] is True
    assert res_search["count"] > 0
    assert res_search["results"][0]["topic_id"] == "compliance.arch.overview"

    # doc-search negative
    with pytest.raises(ValueError):
        execute("doc-search", query="")
