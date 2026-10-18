"""Focused hardening tests for MCP Server Core Documentation Subsystem (T-03150)."""

import pytest
from aiosh_mcp.mcp_server_core_doc import (
    McpDocTopic,
    McpServerCoreDocCatalog,
    sanitize_doc_query,
    validate_topic_id,
    MAX_TOPICS_LIMIT,
    MCPDOC_ERR_CAPACITY,
)
from aiosh_mcp.server import mcp


def test_hardening_nfkc_normalization():
    # Full-width characters normalized via NFKC
    fullwidth_query = "ｆａｓｔｍｃｐ"
    clean = sanitize_doc_query(fullwidth_query)
    assert clean == "fastmcp"

    fullwidth_id = "ｃｏｒｅ．ｏｖｅｒｖｉｅｗ"
    # Should normalize and validate cleanly
    validate_topic_id(fullwidth_id)


def test_hardening_topic_capacity_overflow():
    catalog = McpServerCoreDocCatalog()
    for i in range(MAX_TOPICS_LIMIT):
        catalog.register(
            McpDocTopic(
                topic_id=f"topic.{i}",
                title=f"Topic {i}",
                category="test",
                summary="Summary",
                content="Content",
            )
        )
    # Attempting to register topic #257 must raise capacity error
    with pytest.raises(ValueError) as exc_info:
        catalog.register(
            McpDocTopic(
                topic_id="topic.overflow",
                title="Overflow",
                category="test",
                summary="Overflow",
                content="Overflow",
            )
        )
    assert MCPDOC_ERR_CAPACITY in str(exc_info.value)


@pytest.mark.anyio
async def test_hardening_error_path_redaction():
    # Pass an invalid topic containing a Windows file path
    res = await mcp.call_tool(
        "aios_mcp_doc_lookup",
        {"topic_id": "C:\\Windows\\System32\\cmd.exe"}
    )
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert '"ok": false' in data.lower()
    # Check that literal path is redacted or refused without disclosing system internals
    assert "C:\\Windows\\System32" not in data
