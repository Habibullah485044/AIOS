"""Integration tests for MCP Server Core Documentation Subsystem (T-03148)."""

import pytest
from aiosh_mcp.server import mcp


def test_mcp_doc_tool_registered():
    tool_names = [t.name for t in mcp._tool_manager.list_tools()]
    assert "aios_mcp_doc_lookup" in tool_names


@pytest.mark.anyio
async def test_mcp_doc_lookup_list_all():
    res = await mcp.call_tool("aios_mcp_doc_lookup", {})
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert '"ok": true' in data.lower()
    assert "core.overview" in data
    assert "core.policy" in data


@pytest.mark.anyio
async def test_mcp_doc_lookup_get_topic():
    res = await mcp.call_tool("aios_mcp_doc_lookup", {"topic_id": "core.policy"})
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert '"ok": true' in data.lower()
    assert "Zero Escalation" in data
    assert "security" in data


@pytest.mark.anyio
async def test_mcp_doc_lookup_search():
    res = await mcp.call_tool("aios_mcp_doc_lookup", {"query": "fastmcp"})
    assert res is not None
    data = res[0].text if hasattr(res[0], "text") else str(res[0])
    assert '"ok": true' in data.lower()
    assert "core.overview" in data
