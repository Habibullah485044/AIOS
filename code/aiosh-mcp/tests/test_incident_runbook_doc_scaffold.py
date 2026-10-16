"""Scaffold tests for Incident Response Runbooks Documentation Subsystem (T-03045)."""

import pytest

from aiosh_mcp.incident_runbook_doc import (
    RunbookDocCategory,
    RunbookDocRepository,
    sanitize_doc_query,
    validate_topic_id,
    IRDOC_ERR_NOT_FOUND,
)


def test_doc_scaffold_default_initialization():
    repo = RunbookDocRepository()
    topics = repo.list_topics()
    assert len(topics) == 7

    arch_topics = repo.list_by_category(RunbookDocCategory.ARCHITECTURE)
    assert len(arch_topics) >= 1

    topic = repo.get_topic("runbook.arch.overview")
    assert topic is not None
    assert topic.category == RunbookDocCategory.ARCHITECTURE
    assert len(topic.sections) >= 1
    assert len(topic.to_markdown()) > 0


def test_doc_scaffold_query_sanitization_and_validation():
    assert sanitize_doc_query("  malware   scan  ") == "malware   scan"
    assert sanitize_doc_query("test\u200Bzero") == "testzero"

    validate_topic_id("runbook.arch.overview")

    with pytest.raises(ValueError, match=IRDOC_ERR_NOT_FOUND):
        validate_topic_id("")

    with pytest.raises(ValueError, match=IRDOC_ERR_NOT_FOUND):
        validate_topic_id("../secret")

    with pytest.raises(ValueError, match=IRDOC_ERR_NOT_FOUND):
        validate_topic_id(".hidden")

    with pytest.raises(ValueError, match=IRDOC_ERR_NOT_FOUND):
        validate_topic_id("invalid/path")
