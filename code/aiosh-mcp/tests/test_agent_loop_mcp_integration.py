"""Integration tests for the Agent Loop Hardening MCP/API surface (T-03298).

Spawns the production stdio server (`python -m aiosh_mcp.server`) and talks to it with
the official MCP client: discovery (tools/list with schema limits and annotations),
a full loop over JSON-RPC against $AIOSH_HOME/audit.db, and parity of the audit trail
with the CLI reading the same shared ring.
"""

import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent_loop_grants import mint_grant, verify_chain
from aiosh_mcp.agent_loop_cli import dispatch_cli
from aiosh_mcp.agent_loop_mcp import TOOL_ANNOTATIONS

PKG_ROOT = Path(__file__).resolve().parents[1]


def _server(home: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable, args=["-m", "aiosh_mcp.server"], cwd=str(PKG_ROOT),
        env=dict(os.environ, AIOSH_HOME=str(home)),
    )


def _data(result) -> dict:
    assert not result.isError, result.content
    return json.loads(result.content[0].text)


@pytest.mark.anyio
async def test_stdio_discovery_publishes_limits_and_annotations(tmp_path):
    async with stdio_client(_server(tmp_path)) as (r, w), ClientSession(r, w) as session:
        await session.initialize()
        tools = {t.name: t for t in (await session.list_tools()).tools}
    for name, ann in TOOL_ANNOTATIONS.items():
        assert name in tools, name
        got = tools[name].annotations
        assert (got.readOnlyHint, got.destructiveHint, got.idempotentHint) == \
            (ann.readOnlyHint, ann.destructiveHint, ann.idempotentHint), name
    adv = tools["aios_agent_loop_advance"].inputSchema["properties"]
    assert adv["action_intent"]["maxLength"] == 4096
    assert adv["tokens_consumed"]["maximum"] == 1_000_000


@pytest.mark.anyio
async def test_stdio_full_loop_and_cli_parity(tmp_path):
    db = tmp_path / "audit.db"
    mint_grant(str(db), "gr_mcp_integ", tools=["aios.agent_loop.start", "aios.fs.read"])
    lid, tok = "loop-mcp-integ-01", "gr_mcp_integ"
    async with stdio_client(_server(tmp_path)) as (r, w), ClientSession(r, w) as session:
        await session.initialize()
        start = _data(await session.call_tool("aios_agent_loop_start", {"loop_id": lid, "capability_token": tok}))
        assert start["ok"], start
        ok = _data(await session.call_tool("aios_agent_loop_advance", {
            "loop_id": lid, "action_intent": "read", "tool_name": "aios.fs.read", "capability_token": tok}))
        no = _data(await session.call_tool("aios_agent_loop_advance", {
            "loop_id": lid, "action_intent": "write", "tool_name": "fs.write", "capability_token": tok}))
        assert (ok["data"]["step"]["outcome"], no["data"]["step"]["outcome"]) == ("ok", "refused")
        done = _data(await session.call_tool("aios_agent_loop_complete", {"loop_id": lid, "capability_token": tok}))
        assert done["data"]["snapshot"]["current_state"] == "COMPLETED"
        mcp_hist = _data(await session.call_tool("aios_agent_loop_history", {"loop_id": lid}))["data"]["events"]
        status = _data(await session.call_tool("aios_agent_loop_status", {"loop_id": lid}))
        assert status["ok"] and status["snapshot"]["current_state"] == "COMPLETED"

        bad = await session.call_tool("aios_agent_loop_start", {"loop_id": "bad"})
        assert bad.isError

    cli_hist = dispatch_cli(["history", "--loop-id", lid], db_path=str(db)).data["events"]
    assert mcp_hist == cli_hist
    assert [e["tool"] for e in mcp_hist] == [
        "aios.agent_loop.start", "aios.agent_loop.step", "aios.agent_loop.step", "aios.agent_loop.complete"]
    assert verify_chain(str(db)).get("ok") is True
