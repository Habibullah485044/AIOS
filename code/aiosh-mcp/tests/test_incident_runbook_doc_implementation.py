"""Implementation tests for Incident Response Runbooks Documentation Subsystem (T-03046)."""

import pytest

from aiosh_mcp.incident_runbook_doc import (
    RunbookDocCategory,
    RunbookDocRepository,
    RunbookDocSection,
    RunbookDocTopic,
    IRDOC_ERR_QUERY_BOUNDS,
    MAX_RUNBOOK_DOC_QUERY_LEN,
)
from aiosh_mcp.incident_runbook_mcp import execute_runbook_core


def test_doc_implementation_topics_retrieval_and_markdown():
    repo = RunbookDocRepository()
    topic = repo.get_topic("runbook.arch.overview")
    assert topic is not None
    assert topic.id == "runbook.arch.overview"
    assert topic.category == RunbookDocCategory.ARCHITECTURE
    assert len(topic.sections) >= 2
    assert len(topic.related_topics) >= 1

    md = topic.to_markdown()
    assert "# Incident Response Runbooks Architecture" in md
    assert "## Core Architecture" in md
    assert "### Related Topics" in md


def test_doc_implementation_add_topic_mutation():
    repo = RunbookDocRepository()
    initial_count = len(repo.list_topics())

    custom = RunbookDocTopic(
        id="runbook.custom.test",
        title="Custom Runbook Topic",
        category=RunbookDocCategory.DATAMODEL,
        summary="Custom topic summary",
        sections=[RunbookDocSection(title="Custom Section", content="Custom content")],
        related_topics=[],
    )

    repo.add_topic(custom)
    assert len(repo.list_topics()) == initial_count + 1
    assert repo.get_topic("runbook.custom.test") is not None


def test_doc_implementation_search_ranking_and_filtering():
    repo = RunbookDocRepository()

    # 1. Search for "architecture" returns top hit with high score
    results = repo.search("architecture")
    assert len(results) > 0
    assert results[0].topic_id == "runbook.arch.overview"
    assert results[0].score >= 10

    # 2. Search with category filter
    filtered = repo.search("runbook", category=RunbookDocCategory.OBSERVABILITY)
    assert len(filtered) > 0
    for res in filtered:
        assert res.category == RunbookDocCategory.OBSERVABILITY

    # 3. Search bounds error on empty or oversized
    with pytest.raises(ValueError, match=IRDOC_ERR_QUERY_BOUNDS):
        repo.search("   ")

    with pytest.raises(ValueError, match=IRDOC_ERR_QUERY_BOUNDS):
        repo.search("a" * (MAX_RUNBOOK_DOC_QUERY_LEN + 1))


def test_doc_implementation_mcp_actions():
    # 1. doc_list
    res_list = execute_runbook_core(action="doc_list")
    assert res_list["ok"] is True
    assert res_list["action"] == "doc_list"
    assert len(res_list["topics"]) >= 7

    # 2. doc_get
    res_get = execute_runbook_core(action="doc_get", runbook_id="runbook.arch.overview")
    assert res_get["ok"] is True
    assert res_get["action"] == "doc_get"
    assert res_get["topic"]["id"] == "runbook.arch.overview"
    assert "markdown" in res_get["topic"]

    # 3. doc_search
    res_search = execute_runbook_core(action="doc_search", parameters={"query": "telemetry"})
    assert res_search["ok"] is True
    assert res_search["action"] == "doc_search"
    assert len(res_search["results"]) > 0
    assert any(r["topic_id"] == "runbook.observability.telemetry" for r in res_search["results"])
