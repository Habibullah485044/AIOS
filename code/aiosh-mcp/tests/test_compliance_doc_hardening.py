"""Hardening verification tests for Compliance Mapping Documentation Subsystem (T-02950)."""

import pytest

from aiosh_mcp.compliance_doc import (
    COMPLYDOC_ERR_NOT_FOUND,
    COMPLYDOC_ERR_QUERY_BOUNDS,
    ComplianceDocRepository,
    sanitize_doc_query,
    validate_topic_id,
)


def test_hardening_bidi_and_invisible_filtering() -> None:
    injected = "search\u202Equery\u200Bwith\uFEFFhidden"
    cleaned = sanitize_doc_query(injected)
    assert cleaned == "searchquerywithhidden"


def test_hardening_topic_id_boundary_rules() -> None:
    # Valid IDs
    validate_topic_id("compliance.arch.overview")
    validate_topic_id("my_custom-topic.1")

    # Boundary dots / hyphens rejected
    with pytest.raises(ValueError) as exc:
        validate_topic_id(".compliance.arch")
    assert COMPLYDOC_ERR_NOT_FOUND in str(exc.value)

    with pytest.raises(ValueError) as exc:
        validate_topic_id("compliance.arch.")
    assert COMPLYDOC_ERR_NOT_FOUND in str(exc.value)

    with pytest.raises(ValueError) as exc:
        validate_topic_id("-compliance.arch")
    assert COMPLYDOC_ERR_NOT_FOUND in str(exc.value)

    with pytest.raises(ValueError) as exc:
        validate_topic_id("compliance.arch-")
    assert COMPLYDOC_ERR_NOT_FOUND in str(exc.value)

    # Forbidden characters rejected
    with pytest.raises(ValueError) as exc:
        validate_topic_id("compliance$arch")
    assert COMPLYDOC_ERR_NOT_FOUND in str(exc.value)

    with pytest.raises(ValueError) as exc:
        validate_topic_id("compliance@arch")
    assert COMPLYDOC_ERR_NOT_FOUND in str(exc.value)

    with pytest.raises(ValueError) as exc:
        validate_topic_id("compliance arch")
    assert COMPLYDOC_ERR_NOT_FOUND in str(exc.value)


def test_hardening_search_bounds_and_empty_clean_query() -> None:
    repo = ComplianceDocRepository()

    purely_invisible = "\u200B\u202E\x00\x1b"
    with pytest.raises(ValueError) as exc:
        repo.search(purely_invisible)
    assert COMPLYDOC_ERR_QUERY_BOUNDS in str(exc.value)

    with pytest.raises(ValueError) as exc:
        repo.search("     \t\r\n     ")
    assert COMPLYDOC_ERR_QUERY_BOUNDS in str(exc.value)
