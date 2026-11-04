"""Integration tests for Agent Loop Hardening configuration (T-03308).

Each consumer is driven through its production surface with an env override and
must honour it: service capacity, gate busy timeout, MCP start defaults / call
timeout / page budget / snapshot tail, CLI run defaults, plus parity between the
read-only MCP `aios_agent_loop_config` tool and `agent_loop_cli config`.
"""

import json
import os
import sys
from contextlib import closing
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp import FastMCP

from agent_loop_grants import AllowAllGate, mint_grant
from aiosh_mcp import agent_loop_config as alc
from aiosh_mcp.agent_loop_cli import dispatch_cli
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_mcp import register_agent_loop_mcp_tools
from aiosh_mcp.agent_loop_service import AgentLoopService, AgentLoopServiceError, LOOPSERV_ERR_CAPACITY
from aiosh_mcp.agent_loop_data_model import LoopConfig

PKG_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    for f in alc.FIELDS.values():
        monkeypatch.delenv(f.env, raising=False)
    monkeypatch.delenv(alc.ENV_AGENT_LOOP_CONFIG, raising=False)
    monkeypatch.chdir(tmp_path)
    # Degraded-config audit rows (T-03310) must never reach the developer's real ring.
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path))
    alc.reset_process_config()
    yield
    alc.reset_process_config()


async def call(app, name, args):
    res = await app._tool_manager.call_tool(name, args)
    res = res[0] if isinstance(res, tuple) else res
    return json.loads(res[0].text) if isinstance(res, list) else res


def test_service_capacity_from_env(monkeypatch):
    monkeypatch.setenv("AIOSH_AGENT_LOOP_REGISTRY_CAPACITY", "2")
    svc = AgentLoopService(gate=AllowAllGate())
    svc.start_loop(LoopConfig(loop_id="loop-cfgint-cap1"), capability_token="t")
    svc.start_loop(LoopConfig(loop_id="loop-cfgint-cap2"), capability_token="t")
    with pytest.raises(AgentLoopServiceError) as exc:
        svc.start_loop(LoopConfig(loop_id="loop-cfgint-cap3"), capability_token="t")
    assert exc.value.code == LOOPSERV_ERR_CAPACITY


def test_gate_busy_timeout_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOSH_AGENT_LOOP_DB_BUSY_TIMEOUT_MS", "1234")
    gate = PepCapabilityGate(str(tmp_path / "audit.db"))
    with closing(gate._open()) as conn:
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 1234


@pytest.mark.anyio
async def test_mcp_start_uses_configured_defaults_and_explicit_wins(monkeypatch):
    monkeypatch.setenv("AIOSH_AGENT_LOOP_MAX_ITERATIONS", "7")
    monkeypatch.setenv("AIOSH_AGENT_LOOP_SNAPSHOT_STEPS_TAIL", "1")
    svc = AgentLoopService(gate=AllowAllGate())
    app = FastMCP("cfg-int")
    register_agent_loop_mcp_tools(app, service=svc)
    await call(app, "aios_agent_loop_start", {"loop_id": "loop-cfgint-mcp1", "capability_token": "t"})
    await call(app, "aios_agent_loop_start", {"loop_id": "loop-cfgint-mcp2", "capability_token": "t",
                                              "max_iterations": 3})
    assert svc._configs["loop-cfgint-mcp1"].max_iterations == 7
    assert svc._configs["loop-cfgint-mcp2"].max_iterations == 3
    for _ in range(3):
        await call(app, "aios_agent_loop_advance", {"loop_id": "loop-cfgint-mcp1", "action_intent": "x",
                                                    "capability_token": "t"})
    snap = (await call(app, "aios_agent_loop_snapshot", {"loop_id": "loop-cfgint-mcp1"}))["data"]
    assert (len(snap["snapshot"]["steps"]), snap["steps_total"]) == (1, 3)


def test_cli_run_uses_configured_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOSH_AGENT_LOOP_MAX_ITERATIONS", "1")
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"turns": [{"action_intent": f"t{i}"} for i in range(3)]}), encoding="utf-8")
    res = dispatch_cli(["run", "--loop-id", "loop-cfgint-cli1", "--token", "t", "--plan", str(plan)],
                       service=AgentLoopService(gate=AllowAllGate()))
    assert (res.data["final_state"], res.data["turns_skipped"]) == ("FAILED", 2)


@pytest.mark.anyio
async def test_mcp_config_tool_matches_cli_config(monkeypatch, tmp_path):
    cfg_file = tmp_path / "loop.json"
    cfg_file.write_text(json.dumps({"history_page_bytes": 70000}), encoding="utf-8")
    monkeypatch.setenv(alc.ENV_AGENT_LOOP_CONFIG, str(cfg_file))
    monkeypatch.setenv("AIOSH_AGENT_LOOP_MCP_CALL_TIMEOUT_S", "nan")
    app = FastMCP("cfg-parity")
    register_agent_loop_mcp_tools(app, service=AgentLoopService(gate=AllowAllGate()))
    mcp_view = (await call(app, "aios_agent_loop_config", {}))["data"]
    cli_view = dispatch_cli(["config", "--json"]).data
    assert json.dumps(mcp_view, sort_keys=True) == json.dumps(cli_view, sort_keys=True)
    assert mcp_view["source"]["history_page_bytes"] == "file"
    assert mcp_view["source"]["mcp_call_timeout_s"] == "default"
    assert mcp_view["rejected"]["mcp_call_timeout_s"] == "env_invalid"
    assert mcp_view["config"]["mcp_call_timeout_s"] == 15.0


@pytest.mark.anyio
async def test_stdio_server_reports_env_config(tmp_path):
    env = dict(os.environ, AIOSH_HOME=str(tmp_path), AIOSH_AGENT_LOOP_REGISTRY_CAPACITY="9")
    params = StdioServerParameters(command=sys.executable, args=["-m", "aiosh_mcp.server"], cwd=str(PKG_ROOT), env=env)
    async with stdio_client(params) as (r, w), ClientSession(r, w) as session:
        await session.initialize()
        tools = {t.name: t for t in (await session.list_tools()).tools}
        assert tools["aios_agent_loop_config"].annotations.readOnlyHint is True
        out = json.loads((await session.call_tool("aios_agent_loop_config", {})).content[0].text)["data"]
    assert (out["config"]["registry_capacity"], out["source"]["registry_capacity"]) == (9, "env")
