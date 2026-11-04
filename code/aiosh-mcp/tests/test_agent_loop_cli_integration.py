"""Integration tests for the Agent Loop Hardening CLI surface (T-03288).

Exercises the production call paths: the `aiosh-agent-loop` console-script
declaration, a real `python -m aiosh_mcp.agent_loop_cli` subprocess against
$AIOSH_HOME/audit.db, and parity between a loop driven through the CLI and the
same plan driven through the MCP tools on one shared audit ring.
"""

import importlib
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from agent_loop_grants import mint_grant, verify_chain
from aiosh_mcp.agent_loop_cli import dispatch_cli
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_service import AgentLoopService, _GLOBAL_AGENT_LOOP_SERVICE
from aiosh_mcp.server import mcp

PKG_ROOT = Path(__file__).resolve().parents[1]
PLAN = {"turns": [
    {"action_intent": "read README", "tool_name": "aios.fs.read", "tool_args": {"path": "README.md"},
     "tokens_consumed": 120},
    {"action_intent": "write file", "tool_name": "fs.write"},
    {"action_intent": "think"},
]}


@pytest.fixture
def home(tmp_path):
    db = tmp_path / "audit.db"
    for gid in ("gr_cli_integ_cli", "gr_cli_integ_mcp"):
        mint_grant(str(db), gid, tools=["aios.agent_loop.start", "aios.fs.read"])
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(PLAN), encoding="utf-8")
    return tmp_path, str(db), str(plan)


def test_console_script_declared_and_resolves():
    meta = tomllib.loads((PKG_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    target = meta["project"]["scripts"]["aiosh-agent-loop"]
    module, func = target.split(":")
    assert callable(getattr(importlib.import_module(module), func))


def test_python_m_subprocess_uses_aiosh_home(home):
    tmp, db, plan = home
    env = dict(os.environ, AIOSH_HOME=str(tmp))
    run = subprocess.run(
        [sys.executable, "-m", "aiosh_mcp.agent_loop_cli", "run", "--loop-id", "loop-cli-integ-proc",
         "--token", "gr_cli_integ_cli", "--plan", plan, "--json"],
        cwd=PKG_ROOT, env=env, capture_output=True, text=True, timeout=60,
    )
    payload = json.loads(run.stdout)
    assert run.returncode == payload["exit_code"] == 0
    assert payload["data"]["final_state"] == "COMPLETED"

    hist = subprocess.run(
        [sys.executable, "-m", "aiosh_mcp.agent_loop_cli", "history", "--loop-id", "loop-cli-integ-proc", "--json"],
        cwd=PKG_ROOT, env=env, capture_output=True, text=True, timeout=60,
    )
    events = json.loads(hist.stdout)["data"]["events"]
    assert [e["tool"].rsplit(".", 1)[1] for e in events] == ["start", "step", "step", "step", "complete"]
    assert verify_chain(db).get("ok") is True


def _mcp_payload(res):
    if isinstance(res, tuple):
        res = res[0]
    if isinstance(res, list):
        return json.loads(res[0].text)
    return res


@pytest.mark.anyio
async def test_cli_and_mcp_parity_on_shared_ring(home, monkeypatch):
    """Same plan via CLI and via MCP tools -> same step outcomes and same audit event shape."""
    tmp, db, plan = home
    cli = dispatch_cli(["run", "--loop-id", "loop-cli-integ-cli", "--token", "gr_cli_integ_cli", "--plan", plan],
                       service=AgentLoopService(gate=PepCapabilityGate(db)), db_path=db)
    assert cli.exit_code == 0

    monkeypatch.setattr(_GLOBAL_AGENT_LOOP_SERVICE, "_gate", PepCapabilityGate(db))
    lid, tok = "loop-cli-integ-mcp", "gr_cli_integ_mcp"
    try:
        await mcp._tool_manager.call_tool("aios_agent_loop_start", {"loop_id": lid, "capability_token": tok})
        mcp_steps = []
        for turn in PLAN["turns"]:
            res = _mcp_payload(await mcp._tool_manager.call_tool(
                "aios_agent_loop_advance", {"loop_id": lid, "capability_token": tok, **turn}))
            mcp_steps.append(res["data"]["step"])
        _GLOBAL_AGENT_LOOP_SERVICE.complete_loop(lid, capability_token=tok)
    finally:
        for table in ("_loops", "_configs", "_start_times", "_grants"):
            getattr(_GLOBAL_AGENT_LOOP_SERVICE, table).pop(lid, None)

    def shape(steps):
        return [(s["step_index"], s["tool_name"], s["outcome"], s["tokens_consumed"]) for s in steps]

    assert shape(cli.data["turns"]) == shape(mcp_steps)

    def events(loop_id):
        evs = dispatch_cli(["history", "--loop-id", loop_id], db_path=db).data["events"]
        return [(e["tool"], e["outcome"]) for e in evs]

    assert events("loop-cli-integ-cli") == events(lid)
    assert verify_chain(db).get("ok") is True
