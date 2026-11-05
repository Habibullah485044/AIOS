"""Integration tests for agent-loop observability (T-03338).

Production paths: aios_agent_loop_metrics over the real stdio MCP server after a loop ran
through it, and `agent_loop_cli metrics` reading the same ring (parity of the ring view).
"""

import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent_loop_grants import mint_grant
from aiosh_mcp.agent_loop_cli import EXIT_SUCCESS, EXIT_USAGE, dispatch_cli, render

PKG_ROOT = Path(__file__).resolve().parents[1]
GRANT = "gr_obsint_secret_0001"


@pytest.mark.anyio
async def test_stdio_metrics_after_a_loop_and_cli_parity(tmp_path):
    db = tmp_path / "audit.db"
    mint_grant(str(db), GRANT, tools=["aios.agent_loop.start", "aios.fs.*", "fs.*"])
    params = StdioServerParameters(command=sys.executable, args=["-m", "aiosh_mcp.server"], cwd=str(PKG_ROOT),
                                   env=dict(os.environ, AIOSH_HOME=str(tmp_path)))
    lid = "loop-obsint-01"
    async with stdio_client(params) as (r, w), ClientSession(r, w) as session:
        await session.initialize()

        async def call(name, args):
            return json.loads((await session.call_tool(name, args)).content[0].text)

        tools = {t.name: t for t in (await session.list_tools()).tools}
        assert tools["aios_agent_loop_metrics"].annotations.readOnlyHint is True
        await call("aios_agent_loop_start", {"loop_id": lid, "capability_token": GRANT})
        await call("aios_agent_loop_advance", {"loop_id": lid, "action_intent": "r", "tool_name": "aios.fs.read",
                                               "tool_args": {"path": "README.md"}, "capability_token": GRANT})
        await call("aios_agent_loop_advance", {"loop_id": lid, "action_intent": "w", "tool_name": "fs.write",
                                               "tool_args": {"path": "/tmp/x"}, "capability_token": GRANT})
        await call("aios_agent_loop_complete", {"loop_id": lid, "capability_token": GRANT})
        m = (await call("aios_agent_loop_metrics", {}))["data"]
        bad_window = await session.call_tool("aios_agent_loop_metrics", {"window": 0})
    assert bad_window.isError
    assert m["health"] == "ok"
    assert m["ring"]["steps"] | {"duration_ms": None} == {"ok": 1, "refused": 1, "irreversible_ok": 0,
                                                          "duration_ms": None}
    assert m["ring"]["refusals"]["constitution"] == 1
    assert m["live"]["counters"]["steps_ok"] == 1 and m["live"]["counters"]["steps_refused"] == 1
    assert GRANT not in json.dumps(m)

    cli = dispatch_cli(["metrics", "--json"], db_path=str(db))
    assert cli.exit_code == EXIT_SUCCESS
    assert cli.data["ring"] == m["ring"]                         # same ring, same view from MCP and CLI
    text = render(cli, json_mode=False)
    assert text.splitlines()[0] == "health: ok" and "constitution=1" in text
    assert dispatch_cli(["metrics", "--window", "0"], db_path=str(db)).exit_code == EXIT_USAGE
