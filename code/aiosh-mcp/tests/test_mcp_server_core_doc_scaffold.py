"""Unit tests for MCP Server Core Documentation scaffold (T-03145)."""

import pytest
from aiosh_mcp.mcp_server_core_doc import (
    McpDocTopic,
    McpDocSearchResult,
    McpServerCoreDocCatalog,
    sanitize_doc_query,
    validate_topic_id,
    MAX_MCP_DOC_QUERY_LEN,
    MAX_MCP_DOC_SEARCH_RESULTS,
)


def test_mcp_doc_scaffold_types():
    topic = McpDocTopic(
        topic_id="core.overview",
        title="Core Overview",
        category="architecture",
        summary="Overview of MCP server core",
        content="Detailed documentation here.",
        keywords=["core", "overview"],
        cross_references=["core.api"],
    )
    assert topic.topic_id == "core.overview"
    assert topic.to_dict()["title"] == "Core Overview"

    search_res = McpDocSearchResult(
        topic_id="core.overview",
        title="Core Overview",
        category="architecture",
        summary="Overview of MCP server core",
        score=2,
    )
    assert search_res.score == 2
    assert search_res.to_dict()["score"] == 2


def test_mcp_doc_scaffold_catalog():
    catalog = McpServerCoreDocCatalog()
    topic = McpDocTopic(
        topic_id="core.overview",
        title="Core Overview",
        category="architecture",
        summary="Overview of MCP server core",
        content="Detailed documentation content.",
        keywords=["architecture", "spine"],
    )
    catalog.register(topic)
    assert catalog.list_topics() == ["core.overview"]
    assert catalog.get("core.overview").title == "Core Overview"

    results = catalog.search("spine")
    assert len(results) == 1
    assert results[0].topic_id == "core.overview"


def test_mcp_doc_scaffold_validation():
    validate_topic_id("valid.topic-123_id")
    with pytest.raises(ValueError):
        validate_topic_id("../traversal")
    with pytest.raises(ValueError):
        validate_topic_id("")
    with pytest.raises(ValueError):
        validate_topic_id("topic/with/slash")
