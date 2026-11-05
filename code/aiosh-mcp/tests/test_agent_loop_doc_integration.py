"""Integration test for the agent-loop generated reference (T-03348): real stdio MCP server + CLI parity."""

import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from aiosh_mcp.agent_loop_cli import EXIT_SUCCESS, dispatch_cli

PKG_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.anyio
async def test_stdio_doc_tool_and_cli_parity(tmp_path):
    params = StdioServerParameters(command=sys.executable, args=["-m", "aiosh_mcp.server"], cwd=str(PKG_ROOT),
                                   env=dict(os.environ, AIOSH_HOME=str(tmp_path)))
    async with stdio_client(params) as (r, w), ClientSession(r, w) as session:
        await session.initialize()
        tools = {t.name: t for t in (await session.list_tools()).tools}
        assert tools["aios_agent_loop_doc"].annotations.readOnlyHint is True
        assert tools["aios_agent_loop_doc"].inputSchema["properties"]["section"]["anyOf"][0]["enum"] == [
            "tools", "errors", "config", "cli", "policy"]
        errors = json.loads((await session.call_tool("aios_agent_loop_doc", {"section": "errors"})).content[0].text)
        everything = json.loads((await session.call_tool("aios_agent_loop_doc", {})).content[0].text)
        bad = await session.call_tool("aios_agent_loop_doc", {"section": "secrets"})
    assert bad.isError
    assert len(errors["data"]["errors"]) == 34
    assert {t["name"] for t in everything["data"]["tools"]} == {n for n in tools if n.startswith("aios_agent_loop_")}
    cli = dispatch_cli(["doc", "--section", "errors", "--json"])
    assert cli.exit_code == EXIT_SUCCESS and cli.data == errors["data"]
