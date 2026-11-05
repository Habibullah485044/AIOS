"""Integration tests for the agent-loop security policy (T-03328).

Production paths: a TS-issued grant's --max-irreversible budget enforced by the Python loop,
policy verdicts surfaced over the real stdio MCP server, and in the CLI run output.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent_loop_grants import mint_grant, verify_chain
from aiosh_mcp.agent_loop_cli import dispatch_cli, render
from aiosh_mcp.agent_loop_data_model import LoopConfig
from aiosh_mcp.agent_loop_gate import PepCapabilityGate, read_loop_history
from aiosh_mcp.agent_loop_service import AgentLoopService

PKG_ROOT = Path(__file__).resolve().parents[1]
TS_CLI = PKG_ROOT.parent / "aiosh-cli" / "dist" / "cli.js"
NODE = shutil.which("node")


@pytest.mark.skipif(NODE is None or not TS_CLI.is_file(), reason="needs node and a built TS CLI (npm run build)")
def test_ts_max_irreversible_is_enforced_by_python_loop(tmp_path):
    out = subprocess.run([NODE, str(TS_CLI), "grant", "create", "--to", "agent:scanner",
                          "--tools", "aios.agent_loop.start,pentest.*", "--networks", "10.0.0.0/24",
                          "--max-irreversible", "1", "--ttl", "600"],
                         env=dict(os.environ, AIOSH_HOME=str(tmp_path)), capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    gid = json.loads(out.stdout)["data"]["grant_id"]
    db = str(tmp_path / "audit.db")
    svc = AgentLoopService(gate=PepCapabilityGate(db))
    svc.start_loop(LoopConfig(loop_id="loop-polint-ts"), capability_token=gid)
    first = svc.advance_turn("loop-polint-ts", "scan", tool_name="pentest.nmap", tool_args={"target": "10.0.0.5"},
                             capability_token=gid)
    second = svc.advance_turn("loop-polint-ts", "scan", tool_name="pentest.nmap", tool_args={"target": "10.0.0.6"},
                              capability_token=gid)
    assert (first.outcome, second.outcome) == ("ok", "refused")
    assert "LOOPPOL_ERR_IRREVERSIBLE_BUDGET: used 1 of 1" in second.error_message
    assert verify_chain(db).get("ok") is True


@pytest.mark.anyio
async def test_stdio_mcp_surfaces_policy_verdicts(tmp_path):
    db = tmp_path / "audit.db"
    mint_grant(str(db), "gr_polint_mcp", tools=["aios.agent_loop.start", "aios.fs.*", "fs.*"])
    params = StdioServerParameters(command=sys.executable, args=["-m", "aiosh_mcp.server"], cwd=str(PKG_ROOT),
                                   env=dict(os.environ, AIOSH_HOME=str(tmp_path)))
    lid, tok = "loop-polint-mcp", "gr_polint_mcp"
    async with stdio_client(params) as (r, w), ClientSession(r, w) as session:
        await session.initialize()

        async def call(name, args):
            return json.loads((await session.call_tool(name, args)).content[0].text)

        await call("aios_agent_loop_start", {"loop_id": lid, "capability_token": tok})
        ok = (await call("aios_agent_loop_advance", {"loop_id": lid, "action_intent": "read", "tool_name": "aios.fs.read",
                                                     "tool_args": {"path": "README.md"}, "capability_token": tok}))
        bad = (await call("aios_agent_loop_advance", {"loop_id": lid, "action_intent": "write", "tool_name": "fs.write",
                                                      "tool_args": {"path": "/tmp/x"}, "capability_token": tok}))
        hist = (await call("aios_agent_loop_history", {"loop_id": lid}))["data"]["events"]
    assert ok["data"]["step"]["policy"]["verdict"] == "ok"
    assert bad["data"]["step"]["outcome"] == "refused"
    assert "R-03" in bad["data"]["step"]["policy"]["rule_ids"]
    steps = [e for e in hist if e["tool"] == "aios.agent_loop.step"]
    assert [e["verdict"] for e in steps] == ["ok", "refused"]
    assert steps == [e for e in read_loop_history(str(db), lid, 100) if e["tool"] == "aios.agent_loop.step"]


def test_cli_run_shows_rule_ids(tmp_path):
    db = str(tmp_path / "audit.db")
    mint_grant(db, "gr_polint_cli", tools=["aios.agent_loop.start", "fs.*"])
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"turns": [{"action_intent": "w", "tool_name": "fs.write",
                                           "tool_args": {"path": "/tmp/x"}}]}), encoding="utf-8")
    res = dispatch_cli(["run", "--loop-id", "loop-polint-cli", "--token", "gr_polint_cli", "--plan", str(plan)],
                       service=AgentLoopService(gate=PepCapabilityGate(db)), db_path=db)
    line = render(res, json_mode=False).splitlines()[0]
    assert "refused" in line and "R-03" in line and "LOOPPOL_ERR_CONSTITUTION" in line
