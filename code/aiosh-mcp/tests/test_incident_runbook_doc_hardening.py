"""Hardening tests for Incident Response Runbooks Documentation Subsystem (T-03050)."""

import pytest

from aiosh_mcp.incident_runbook_doc import (
    RunbookDocCategory,
    RunbookDocRepository,
    RunbookDocResultEnvelope,
    RunbookDocSection,
    RunbookDocTopic,
    IRDOC_ERR_CAPACITY_EXCEEDED,
    IRDOC_ERR_NOT_FOUND,
    IRDOC_ERR_QUERY_BOUNDS,
    MAX_RUNBOOK_DOC_QUERY_LEN,
    MAX_RUNBOOK_DOC_TEXT_LEN,
    MAX_RUNBOOK_DOC_TOPICS_COUNT,
)
from aiosh_mcp.incident_runbook_mcp import execute_runbook_action


def test_doc_envelope_serialization():
    env_ok = RunbookDocResultEnvelope.success({"foo": "bar"})
    assert env_ok.ok is True
    assert env_ok.data == {"foo": "bar"}
    assert env_ok.error_code is None
    assert env_ok.audit_row_required is False
    d_ok = env_ok.to_dict()
    assert d_ok["ok"] is True
    assert d_ok["data"] == {"foo": "bar"}

    env_err = RunbookDocResultEnvelope.failure("ERR_CODE", "An error occurred")
    assert env_err.ok is False
    assert env_err.error_code == "ERR_CODE"
    assert env_err.error_message == "An error occurred"
    assert env_err.audit_row_required is True
    d_err = env_err.to_dict()
    assert d_err["ok"] is False
    assert d_err["audit_row_required"] is True


def test_get_topic_safe_hardening():
    repo = RunbookDocRepository()

    # Valid topic
    res = repo.get_topic_safe("runbook.arch.overview")
    assert res.ok is True
    assert res.data.id == "runbook.arch.overview"

    # Missing topic
    res_missing = repo.get_topic_safe("runbook.nonexistent")
    assert res_missing.ok is False
    assert res_missing.error_code == IRDOC_ERR_NOT_FOUND
    assert res_missing.audit_row_required is True

    # Malicious path traversal ID
    res_malicious = repo.get_topic_safe("../../etc/shadow")
    assert res_malicious.ok is False
    assert res_malicious.error_code == IRDOC_ERR_NOT_FOUND
    assert res_malicious.audit_row_required is True


def test_search_safe_bounds_hardening():
    repo = RunbookDocRepository()

    # Valid search
    ok_res = repo.search_safe("telemetry")
    assert ok_res.ok is True
    assert len(ok_res.data) > 0

    # Empty search
    empty_res = repo.search_safe("   ")
    assert empty_res.ok is False
    assert empty_res.error_code == IRDOC_ERR_QUERY_BOUNDS
    assert empty_res.audit_row_required is True

    # Oversized search query
    long_res = repo.search_safe("a" * (MAX_RUNBOOK_DOC_QUERY_LEN + 10))
    assert long_res.ok is False
    assert long_res.error_code == IRDOC_ERR_QUERY_BOUNDS
    assert long_res.audit_row_required is True


def test_add_topic_safe_capacity_and_bounds():
    repo = RunbookDocRepository()
    repo.topics = []

    # Populate to capacity
    for i in range(MAX_RUNBOOK_DOC_TOPICS_COUNT):
        topic = RunbookDocTopic(
            id=f"topic.t.{i}",
            title=f"Test {i}",
            category=RunbookDocCategory.ARCHITECTURE,
            summary="Test summary",
        )
        repo.add_topic_safe(topic)

    # Overflow capacity
    overflow = RunbookDocTopic(
        id="topic.t.overflow",
        title="Overflow",
        category=RunbookDocCategory.ARCHITECTURE,
        summary="Overflow summary",
    )
    with pytest.raises(ValueError, match=IRDOC_ERR_CAPACITY_EXCEEDED):
        repo.add_topic_safe(overflow)

    # Updating existing at capacity succeeds
    existing_update = RunbookDocTopic(
        id="topic.t.0",
        title="Updated 0",
        category=RunbookDocCategory.ARCHITECTURE,
        summary="Updated summary",
    )
    repo.add_topic_safe(existing_update)

    # Text limit violations
    huge_summary = RunbookDocTopic(
        id="topic.huge.sum",
        title="Huge",
        category=RunbookDocCategory.ARCHITECTURE,
        summary="x" * (MAX_RUNBOOK_DOC_TEXT_LEN + 10),
    )
    with pytest.raises(ValueError, match=IRDOC_ERR_QUERY_BOUNDS):
        repo.add_topic_safe(huge_summary)


def test_fastmcp_hardening_audit_gates():
    # Calling doc_get with malicious ID yields honest audit row with ok=False
    res_get_err = execute_runbook_action(
        action="doc_get",
        runbook_id="../malicious",
    )
    assert res_get_err["ok"] is False
    assert "audit_id" in res_get_err
    assert IRDOC_ERR_NOT_FOUND in res_get_err["error"]

    # Calling doc_search with empty query yields honest audit row with ok=False
    res_search_err = execute_runbook_action(
        action="doc_search",
        parameters={"query": ""},
    )
    assert res_search_err["ok"] is False
    assert "audit_id" in res_search_err
    assert IRDOC_ERR_QUERY_BOUNDS in res_search_err["error"]
