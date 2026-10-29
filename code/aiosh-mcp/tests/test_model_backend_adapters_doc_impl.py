"""Tests for Model Backend Adapters Documentation Implementation (T-03246)."""

import pytest
from aiosh_mcp.model_backend_adapters_doc import (
    ModelAdapterDocCatalog,
    MODDOC_ERR_INVALID_ID,
)


def test_catalog_initialization():
    catalog = ModelAdapterDocCatalog()
    topics = catalog.list_topics()
    assert len(topics) >= 5
    topic_ids = [t.topic_id for t in topics]
    assert "model.overview" in topic_ids
    assert "model.providers" in topic_ids
    assert "model.fallback" in topic_ids
    assert "model.security" in topic_ids
    assert "model.observability" in topic_ids


def test_get_topic_valid():
    catalog = ModelAdapterDocCatalog()
    topic = catalog.get_topic("model.providers")
    assert topic is not None
    assert topic.topic_id == "model.providers"
    assert "OpenAI" in topic.body
    assert "mock" in topic.tags


def test_get_topic_unknown():
    catalog = ModelAdapterDocCatalog()
    topic = catalog.get_topic("model.unknown_topic")
    assert topic is None


def test_get_topic_traversal_rejected():
    catalog = ModelAdapterDocCatalog()
    with pytest.raises(ValueError, match=MODDOC_ERR_INVALID_ID):
        catalog.get_topic("../secrets.env")


def test_search_scoring():
    catalog = ModelAdapterDocCatalog()
    # Search for "fallback" should score model.fallback highest
    results = catalog.search("fallback cascade")
    assert len(results) > 0
    top = results[0]
    assert top["topic_id"] == "model.fallback"
    assert top["score"] > 0


def test_search_empty_and_bounded():
    catalog = ModelAdapterDocCatalog()
    assert catalog.search("") == []
    assert catalog.search("   ") == []
    results = catalog.search("model", limit=2)
    assert len(results) <= 2
