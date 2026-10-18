"""Unit tests for MCP Server Core Documentation implementation (T-03146)."""

import pytest
from aiosh_mcp.mcp_server_core_doc import (
    build_default_doc_catalog,
    MCPDOC_ERR_NOT_FOUND,
)


def test_default_catalog_has_all_canonical_topics():
    catalog = build_default_doc_catalog()
    topics = catalog.list_topics()
    expected = [
        "core.api",
        "core.config",
        "core.doc",
        "core.observability",
        "core.overview",
        "core.policy",
        "core.tests",
    ]
    assert topics == expected


def test_default_catalog_get_and_content():
    catalog = build_default_doc_catalog()
    topic = catalog.get("core.policy")
    assert topic.category == "security"
    assert "Zero Escalation" in topic.content
    assert "core.overview" in topic.cross_references


def test_default_catalog_search():
    catalog = build_default_doc_catalog()
    results = catalog.search("fastmcp")
    assert len(results) >= 1
    assert any(r.topic_id == "core.overview" for r in results)

    results_policy = catalog.search("authorization")
    assert any(r.topic_id == "core.policy" for r in results_policy)


def test_default_catalog_not_found():
    catalog = build_default_doc_catalog()
    with pytest.raises(KeyError) as exc_info:
        catalog.get("core.nonexistent")
    assert MCPDOC_ERR_NOT_FOUND in str(exc_info.value)
