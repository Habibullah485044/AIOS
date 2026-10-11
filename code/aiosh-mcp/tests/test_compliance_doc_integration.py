"""Integration tests for Compliance Mapping Documentation Subsystem (T-02948)."""

import pytest

from aiosh_mcp.compliance_doc import (
    COMPLYDOC_ERR_NOT_FOUND,
    COMPLYDOC_ERR_QUERY_BOUNDS,
    ComplianceDocCategory,
    ComplianceDocRepository,
)
from aiosh_mcp.server import aios_compliance


def test_compliance_doc_mcp_integration_list_and_get() -> None:
    # 1. doc-list via MCP tool
    res_list = aios_compliance(action="doc-list")
    assert res_list["ok"] is True
    assert res_list["count"] == 7
    assert len(res_list["topics"]) == 7
    assert "audit_id" in res_list

    # 2. doc-get for each topic
    for t_stub in res_list["topics"]:
        res_get = aios_compliance(action="doc-get", id=t_stub["id"])
        assert res_get["ok"] is True
        topic = res_get["topic"]
        assert topic["id"] == t_stub["id"]
        assert topic["category"] == t_stub["category"]
        assert len(topic["sections"]) > 0
        assert "markdown" in topic
        assert f"# {topic['title']}" in topic["markdown"]


def test_compliance_doc_mcp_integration_search_and_por_invariants() -> None:
    # 1. doc-search via MCP tool (Proof of Restraint: grant_id=None succeeds)
    res_search = aios_compliance(action="doc-search", query="regulatory")
    assert res_search["ok"] is True
    assert res_search["count"] > 0
    assert len(res_search["results"]) > 0
    assert "audit_id" in res_search

    # 2. Rejection of invalid query
    res_bad = aios_compliance(action="doc-search", query="")
    assert res_bad["ok"] is False

    res_long = aios_compliance(action="doc-search", query="a" * 130)
    assert res_long["ok"] is False
    assert COMPLYDOC_ERR_QUERY_BOUNDS in res_long["error"]

    # 3. Rejection of traversal / invalid topic ID
    res_traversal = aios_compliance(action="doc-get", id="../secret.txt")
    assert res_traversal["ok"] is False
    assert COMPLYDOC_ERR_NOT_FOUND in res_traversal["error"]


def test_compliance_doc_cross_reference_integrity() -> None:
    repo = ComplianceDocRepository()
    topics = repo.list_topics()
    assert len(topics) == 7

    for topic in topics:
        for rel_id in topic.related_topics:
            rel_topic = repo.get_topic(rel_id)
            assert rel_topic is not None
            assert rel_topic.id == rel_id
