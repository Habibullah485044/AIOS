"""Tests for Model Backend Adapters Documentation Scaffold (T-03245)."""

import pytest
from aiosh_mcp.model_backend_adapters_doc import (
    ModelAdapterDocTopic,
    ModelAdapterDocCatalog,
    sanitize_doc_query,
    validate_topic_id,
    MODDOC_ERR_INVALID_ID,
)


def test_scaffold_types():
    topic = ModelAdapterDocTopic(
        topic_id="test.topic",
        title="Test Title",
        category="core",
        summary="Short summary",
        body="Detailed body text",
        tags=["test", "scaffold"],
    )
    assert topic.topic_id == "test.topic"
    d = topic.to_dict()
    assert d["title"] == "Test Title"
    assert d["tags"] == ["test", "scaffold"]


def test_sanitize_doc_query():
    assert sanitize_doc_query("  hello \x00\x07 world \u200b ") == "hello world"
    long_q = "a" * 200
    assert len(sanitize_doc_query(long_q)) == 128


def test_validate_topic_id():
    validate_topic_id("valid.topic-name_123")
    with pytest.raises(ValueError, match=MODDOC_ERR_INVALID_ID):
        validate_topic_id("../traversal")
    with pytest.raises(ValueError, match=MODDOC_ERR_INVALID_ID):
        validate_topic_id("topic/slash")
    with pytest.raises(ValueError, match=MODDOC_ERR_INVALID_ID):
        validate_topic_id("")


def test_catalog_scaffold_methods_callable():
    catalog = ModelAdapterDocCatalog()
    assert catalog is not None
    topic = catalog.get_topic("model.overview")
    assert topic is not None
    assert topic.topic_id == "model.overview"
