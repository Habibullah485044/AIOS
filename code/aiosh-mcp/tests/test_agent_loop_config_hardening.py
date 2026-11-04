"""Hardening tests for Agent Loop Hardening configuration (T-03310)."""

import json

import pytest
from mcp.server.fastmcp import FastMCP

from agent_loop_grants import AllowAllGate, audit_tools
from aiosh_mcp import agent_loop_config as alc
from aiosh_mcp.agent_loop_cli import EXIT_SUCCESS, EXIT_USAGE, dispatch_cli
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_mcp import register_agent_loop_mcp_tools
from aiosh_mcp.agent_loop_service import AgentLoopService


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    for f in alc.FIELDS.values():
        monkeypatch.delenv(f.env, raising=False)
    monkeypatch.delenv(alc.ENV_AGENT_LOOP_CONFIG, raising=False)
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    alc.reset_process_config()
    yield
    alc.reset_process_config()


async def config_tool(app):
    res = await app._tool_manager.call_tool("aios_agent_loop_config", {})
    res = res[0] if isinstance(res, tuple) else res
    return json.loads(res[0].text)["data"] if isinstance(res, list) else res["data"]


@pytest.mark.anyio
async def test_all_consumers_share_one_resolution(monkeypatch):
    monkeypatch.setenv("AIOSH_AGENT_LOOP_REGISTRY_CAPACITY", "3")
    monkeypatch.setenv("AIOSH_AGENT_LOOP_DB_BUSY_TIMEOUT_MS", "700")
    svc = AgentLoopService(gate=PepCapabilityGate())
    app = FastMCP("cfg-hard-one")
    register_agent_loop_mcp_tools(app, service=svc)
    reported = (await config_tool(app))["config"]
    assert (svc._capacity, svc._gate._busy_ms()) == (reported["registry_capacity"], reported["db_busy_timeout_ms"])
    # A later env change does not split the running process's view.
    monkeypatch.setenv("AIOSH_AGENT_LOOP_REGISTRY_CAPACITY", "99")
    assert AgentLoopService(gate=AllowAllGate())._capacity == 3


@pytest.mark.anyio
async def test_degraded_config_writes_one_honest_audit_row(monkeypatch, tmp_path):
    monkeypatch.setenv("AIOSH_AGENT_LOOP_MCP_CALL_TIMEOUT_S", "soon")
    for name in ("a", "b"):  # two registrations in one process -> still one row
        register_agent_loop_mcp_tools(FastMCP(f"cfg-hard-{name}"), service=AgentLoopService(gate=AllowAllGate()))
    rows = audit_tools(str(tmp_path / "audit.db"))
    assert rows == [("aios.agent_loop.config", "degraded")]
    view = await config_tool(_registered(FastMCP("cfg-hard-c")))
    assert view["degraded"] is True and view["rejected"] == {"mcp_call_timeout_s": "env_invalid"}


def _registered(app):
    register_agent_loop_mcp_tools(app, service=AgentLoopService(gate=AllowAllGate()))
    return app


def test_clean_config_writes_no_row(tmp_path):
    register_agent_loop_mcp_tools(FastMCP("cfg-hard-clean"), service=AgentLoopService(gate=AllowAllGate()))
    assert not (tmp_path / "audit.db").exists() or audit_tools(str(tmp_path / "audit.db")) == []


@pytest.mark.anyio
async def test_unwritable_ring_is_reported_not_raised(monkeypatch, tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    monkeypatch.setenv("AIOSH_HOME", str(blocker))  # audit.db cannot be created under a file
    monkeypatch.setenv("AIOSH_AGENT_LOOP_REGISTRY_CAPACITY", "oops")
    view = await config_tool(_registered(FastMCP("cfg-hard-ro")))
    assert view["degraded"] is True
    assert any("could not audit degraded configuration" in e for e in view["errors"])


def test_cli_strict_mode(monkeypatch):
    assert dispatch_cli(["config", "--strict"]).exit_code == EXIT_SUCCESS
    monkeypatch.setenv("AIOSH_AGENT_LOOP_SNAPSHOT_STEPS_TAIL", "many")
    res = dispatch_cli(["config", "--strict", "--json"])
    assert (res.exit_code, res.error_code) == (EXIT_USAGE, "AGENTLOOPCONF_ERR_STRICT")
    assert res.data["degraded"] is True
    assert dispatch_cli(["config"]).exit_code == EXIT_SUCCESS  # non-strict still reports, exits 0
