"""Unit tests for Incident Response Runbooks Documentation Subsystem (T-03047)."""

import pytest

from aiosh_mcp.incident_runbook_doc import (
    RunbookDocCategory,
    RunbookDocRepository,
    validate_topic_id,
    IRDOC_ERR_NOT_FOUND,
    IRDOC_ERR_QUERY_BOUNDS,
    MAX_RUNBOOK_DOC_QUERY_LEN,
)


def test_unit_case1_valid_input_lookup_and_search():
    repo = RunbookDocRepository()
    topic = repo.get_topic("runbook.tools.scanning")
    assert topic is not None
    assert topic.category == RunbookDocCategory.SECURITY_TOOLS
    assert "aiosh scan" in topic.summary

    hits = repo.search("RustSec")
    assert len(hits) > 0


def test_unit_case2_invalid_input_path_traversal_and_delimiters():
    repo = RunbookDocRepository()

    assert repo.get_topic("") is None
    assert repo.get_topic("../secrets") is None
    assert repo.get_topic("/etc/passwd") is None
    assert repo.get_topic("topic\\nested") is None
    assert repo.get_topic("topic\0null") is None
    assert repo.get_topic(".leading_dot") is None
    assert repo.get_topic("-leading_hyphen") is None


def test_unit_case3_boundary_values_query_length():
    repo = RunbookDocRepository()

    # Query of length exactly 128 chars passes
    exact_128 = "a" * MAX_RUNBOOK_DOC_QUERY_LEN
    res = repo.search(exact_128)
    assert isinstance(res, list)

    # Query of length 129 chars exceeds boundary
    with pytest.raises(ValueError, match=IRDOC_ERR_QUERY_BOUNDS):
        repo.search("a" * (MAX_RUNBOOK_DOC_QUERY_LEN + 1))

    # Whitespace only or empty
    with pytest.raises(ValueError, match=IRDOC_ERR_QUERY_BOUNDS):
        repo.search("")

    with pytest.raises(ValueError, match=IRDOC_ERR_QUERY_BOUNDS):
        repo.search("   ")


def test_unit_case4_primary_failure_mode_unicode_and_not_found():
    repo = RunbookDocRepository()

    # Pure invisible Unicode characters string
    invisible_only = "\u200B\u200C\uFEFF\u202A"
    with pytest.raises(ValueError, match=IRDOC_ERR_QUERY_BOUNDS):
        repo.search(invisible_only)

    # Non-existent topic returns None
    assert repo.get_topic("runbook.nonexistent.entry") is None
