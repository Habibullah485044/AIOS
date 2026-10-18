"""Focused unit tests for MCP Server Core Documentation Subsystem (MCPDOC-INV1..MCPDOC-INV5)."""

import pytest
from aiosh_mcp.mcp_server_core_doc import (
    McpDocTopic,
    McpDocSearchResult,
    McpServerCoreDocCatalog,
    build_default_doc_catalog,
    sanitize_doc_query,
    validate_topic_id,
    MAX_MCP_DOC_QUERY_LEN,
    MAX_MCP_DOC_SEARCH_RESULTS,
    MCPDOC_ERR_INVALID_ID,
    MCPDOC_ERR_NOT_FOUND,
)


def test_mcpdoc_inv1_query_bounds_and_sanitization():
    # Long query clamped to MAX_MCP_DOC_QUERY_LEN (128)
    long_query = "word " * 40
    sanitized = sanitize_doc_query(long_query)
    assert len(sanitized) <= MAX_MCP_DOC_QUERY_LEN

    # Invisible unicode & control character stripping
    dirty = "security\x00\x1f\u200b\ufeffpolicy"
    clean = sanitize_doc_query(dirty)
    assert clean == "securitypolicy"
    assert "\x00" not in clean
    assert "\u200b" not in clean


def test_mcpdoc_inv2_result_clamping():
    catalog = McpServerCoreDocCatalog()
    # Register 15 topics all containing keyword "aios"
    for i in range(15):
        catalog.register(
            McpDocTopic(
                topic_id=f"topic.{i}",
                title=f"Topic {i}",
                category="test",
                summary="AIOS system topic",
                content="Body text",
                keywords=["aios"],
            )
        )
    results = catalog.search("aios")
    assert len(results) == MAX_MCP_DOC_SEARCH_RESULTS  # strictly clamped to 10


def test_mcpdoc_inv3_topic_id_traversal_rejection():
    # Invalid traversal and control sequences
    invalid_ids = [
        "../traversal",
        "topic/path",
        "topic\\backslash",
        "topic\0null",
        "",
        "a" * 65,  # Exceeds max 64 chars
        "topic with spaces",
        "topic#hash",
    ]
    for bad_id in invalid_ids:
        with pytest.raises(ValueError) as exc_info:
            validate_topic_id(bad_id)
        assert MCPDOC_ERR_INVALID_ID in str(exc_info.value)

    # Valid topic IDs
    valid_ids = [
        "core.overview",
        "core_api-v1",
        "SEC-01.policy",
        "test-topic_99",
    ]
    for good_id in valid_ids:
        validate_topic_id(good_id)


def test_mcpdoc_inv4_canonical_topic_data_integrity():
    catalog = build_default_doc_catalog()
    assert len(catalog.list_topics()) == 7

    for topic_id in catalog.list_topics():
        topic = catalog.get(topic_id)
        assert topic.topic_id == topic_id
        assert len(topic.title) > 0
        assert len(topic.summary) > 0
        assert len(topic.content) > 0
        assert isinstance(topic.keywords, list)
        assert len(topic.keywords) > 0
        # Check no sensitive keys or leaked tokens
        assert "PRIVATE KEY" not in topic.content
        assert "password" not in topic.content.lower()


def test_mcpdoc_inv5_search_scoring_and_ranking():
    catalog = build_default_doc_catalog()
    # Query with multiple matching tokens
    results = catalog.search("fastmcp architecture spine")
    assert len(results) >= 1
    assert results[0].topic_id == "core.overview"
    # Ensure descending sort by score
    scores = [r.score for r in results]
    assert scores == sorted(scores, reverse=True)
