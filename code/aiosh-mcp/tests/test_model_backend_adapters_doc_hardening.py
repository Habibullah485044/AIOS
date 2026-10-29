"""Hardening and resilience tests for Model Backend Adapters Documentation (T-03250)."""

import pytest
from aiosh_mcp.model_backend_adapters_doc import (
    ModelAdapterDocTopic,
    ModelAdapterDocCatalog,
    mask_secrets,
    MAX_TOPICS_LIMIT,
    MODDOC_ERR_CAPACITY_EXCEEDED,
    MODDOC_ERR_QUERY_BOUNDS,
    MODDOC_ERR_NOT_FOUND,
    MODDOC_ERR_INVALID_ID,
)


def test_mask_secrets():
    raw = "Header: Bearer sk-ant-api03-abcdef1234567890abcdef1234567890, key=ghp_1234567890abcdef1234567890abcdef"
    masked = mask_secrets(raw)
    assert "sk-ant" not in masked
    assert "ghp_" not in masked
    assert "[REDACTED_SECRET]" in masked


def test_topic_secret_masking_on_export():
    topic = ModelAdapterDocTopic(
        topic_id="secret.leak.test",
        title="Test Secret Masking",
        category="security",
        summary="Contains sk-123456789012345678901234567890",
        body="Sensitive token Bearer secret_token_value_abcdef1234567890",
    )
    d = topic.to_dict()
    assert "[REDACTED_SECRET]" in d["summary"]
    assert "[REDACTED_SECRET]" in d["body"]
    assert "sk-1234567890" not in d["summary"]


def test_catalog_capacity_exceeded():
    catalog = ModelAdapterDocCatalog()
    # Fill up to capacity
    for i in range(len(catalog.list_topics()), MAX_TOPICS_LIMIT):
        catalog.add_topic(
            ModelAdapterDocTopic(
                topic_id=f"test.topic.{i}",
                title=f"Test {i}",
                category="test",
                summary="summary",
                body="body",
            )
        )
    assert len(catalog.list_topics()) == MAX_TOPICS_LIMIT

    # Attempting to add one more topic beyond capacity raises ValueError
    overflow_topic = ModelAdapterDocTopic(
        topic_id="overflow.topic",
        title="Overflow",
        category="test",
        summary="summary",
        body="body",
    )
    with pytest.raises(ValueError, match=MODDOC_ERR_CAPACITY_EXCEEDED):
        catalog.add_topic(overflow_topic)


def test_topic_body_size_bound():
    catalog = ModelAdapterDocCatalog()
    oversized_body = "x" * (65 * 1024)  # 65 KiB > 64 KiB
    oversized_topic = ModelAdapterDocTopic(
        topic_id="oversized.topic",
        title="Oversized",
        category="test",
        summary="summary",
        body=oversized_body,
    )
    with pytest.raises(ValueError, match=MODDOC_ERR_QUERY_BOUNDS):
        catalog.add_topic(oversized_topic)
