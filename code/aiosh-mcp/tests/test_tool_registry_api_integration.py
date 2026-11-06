"""Integration test for the tool registry API surface (T-03398): what a real MCP client sees over stdio."""

import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from aiosh_mcp import tool_registry_api as api
from aiosh_mcp.tool_registry_data_model import Effect, default_catalog

PKG_ROOT = Path(__file__).resolve().parents[1]
C = default_catalog()


@pytest.mark.anyio
async def test_client_sees_catalog_annotations_and_registry_tools(tmp_path):
    params = StdioServerParameters(command=sys.executable, args=["-m", "aiosh_mcp.server"], cwd=str(PKG_ROOT),
                                   env=dict(os.environ, AIOSH_HOME=str(tmp_path)))
    async with stdio_client(params) as (r, w), ClientSession(r, w) as session:
        await session.initialize()
        tools = {t.name: t for t in (await session.list_tools()).tools}

        async def call(name, args):
            res = await session.call_tool(name, args)
            return json.loads(res.content[0].text)

        decision = await call(api.DECIDE_TOOL, {"name": "aios_pentest_nmap"})
        await call(api.DECIDE_TOOL, {"name": "aios.unknown.integration"})
        stats = await call(api.STATS_TOOL, {})
        too_long = await session.call_tool(api.DECIDE_TOOL, {"name": "x" * 300})

    # every tool a client lists carries annotations derived from (and never laxer than) the catalog
    assert all(t.annotations is not None for t in tools.values())
    for name, t in tools.items():
        entry = C.resolve(name)
        assert entry is not None, name
        if t.annotations.readOnlyHint:
            assert entry.effect is Effect.READ_ONLY and not entry.requires_grant, name
    assert tools["aios_pentest_nmap"].annotations.readOnlyHint is False
    assert tools["aios_pentest_nmap"].annotations.openWorldHint is not False
    assert tools["aios_audit_tail"].annotations.readOnlyHint is True

    assert decision["ok"] is True and decision["data"]["canonical"] == "pentest.nmap"
    assert decision["data"]["irreversible"] is True and decision["data"]["target_checked"] is False
    service = stats["data"]["service"]
    assert service["mode"] == "shadow" and service["catalog_entries"] == len(C)   # decide calls are not counted (T-03399)
    assert "unknown.integration" not in json.dumps(stats)
    assert too_long.isError is True                                         # schema bound enforced over the wire
