"""Integration tests for Model Backend Adapters Documentation Subsystem (T-03248)."""

import pytest
from aiosh_mcp.server import mcp
from aiosh_mcp.model_backend_adapters_doc import MODDOC_ERR_INVALID_ID, MODDOC_ERR_NOT_FOUND


@pytest.mark.anyio
async def test_integration_mcp_doc_tools_registration():
    tools = await mcp.list_tools()
    tool_names = [t.name for t in tools]
    assert "aios_model_doc_get" in tool_names
    assert "aios_model_doc_search" in tool_names
    assert "aios_model_doc_list" in tool_names


@pytest.mark.anyio
async def test_integration_mcp_doc_list_call():
    result = await mcp.call_tool("aios_model_doc_list", {})
    assert result is not None
    # Result is a list of TextContent or dict with JSON string
    assert len(result) > 0
    text = result[0].text
    assert '"status": "success"' in text or '"ok": true' in text.lower()
    assert "model.overview" in text
    assert "model.providers" in text


@pytest.mark.anyio
async def test_integration_mcp_doc_get_call_valid():
    result = await mcp.call_tool("aios_model_doc_get", {"topic_id": "model.fallback"})
    assert result is not None
    assert len(result) > 0
    text = result[0].text
    assert '"status": "success"' in text or '"ok": true' in text.lower()
    assert "circuit-breaker" in text or "cascade" in text.lower()


@pytest.mark.anyio
async def test_integration_mcp_doc_get_call_invalid():
    result = await mcp.call_tool("aios_model_doc_get", {"topic_id": "../../secret.env"})
    assert result is not None
    text = result[0].text
    assert MODDOC_ERR_INVALID_ID in text or "error" in text.lower()


@pytest.mark.anyio
async def test_integration_mcp_doc_search_call():
    result = await mcp.call_tool("aios_model_doc_search", {"query": "tokens metering", "limit": 5})
    assert result is not None
    text = result[0].text
    assert '"status": "success"' in text or '"ok": true' in text.lower()
    assert "model.overview" in text or "model.observability" in text
