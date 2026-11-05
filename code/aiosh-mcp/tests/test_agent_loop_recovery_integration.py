"""Integration test for agent-loop recovery & validation (T-03358): real stdio MCP server + CLI."""

import json
import os
import sys
import time
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent_loop_grants import mint_grant
from aiosh_mcp.agent_loop_cli import EXIT_FAILURE, EXIT_SUCCESS, dispatch_cli
from aiosh_mcp.agent_loop_data_model import LoopConfig
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_service import AgentLoopService

PKG_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.anyio
async def test_crash_detect_recover_end_to_end(tmp_path, monkeypatch):
    db = str(tmp_path / "audit.db")
    mint_grant(db, "gr_xrun", tools=["aios.agent_loop.start", "aios.fs.*"])
    mint_grant(db, "gr_xrecover", tools=["aios.agent_loop.recover"])
    crashed = AgentLoopService(gate=PepCapabilityGate(db))          # "another process" that dies mid-loop
    crashed.start_loop(LoopConfig(loop_id="loop-xrec-01", total_timeout_ms=5000), capability_token="gr_xrun")
    crashed.advance_turn("loop-xrec-01", "x", tool_name="aios.fs.read", tool_args={"path": "a"},
                         capability_token="gr_xrun")
    del crashed
    time.sleep(6.2)     # T-03359: a run is orphaned only once its own total timeout (5 s) has passed

    params = StdioServerParameters(command=sys.executable, args=["-m", "aiosh_mcp.server"], cwd=str(PKG_ROOT),
                                   env=dict(os.environ, AIOSH_HOME=str(tmp_path)))
    async with stdio_client(params) as (r, w), ClientSession(r, w) as session:
        await session.initialize()

        async def call(name, args):
            return json.loads((await session.call_tool(name, args)).content[0].text)

        tools = {t.name: t for t in (await session.list_tools()).tools}
        assert tools["aios_agent_loop_validate"].annotations.readOnlyHint is True
        assert tools["aios_agent_loop_recover"].annotations.readOnlyHint is False
        before = (await call("aios_agent_loop_validate", {"grace_s": 0}))["data"]
        metrics = (await call("aios_agent_loop_metrics", {}))["data"]
        forged = await call("aios_agent_loop_recover", {"capability_token": "forged", "grace_s": 0})
        done = (await call("aios_agent_loop_recover", {"capability_token": "gr_xrecover", "grace_s": 0}))["data"]
        after = (await call("aios_agent_loop_validate", {"grace_s": 0}))["data"]
        health_after = (await call("aios_agent_loop_metrics", {}))["data"]["health"]
    assert [o["loop_id"] for o in before["orphaned"]] == ["loop-xrec-01"] and before["ok"] is False
    # Metrics use the default 900 s grace: a crash seconds old is "open", not yet orphaned, so health stays ok.
    assert metrics["ring"]["orphaned_runs"] == 0 and metrics["health"] == "ok"
    assert (forged["ok"], forged["error_code"]) == (False, "LOOPSERV_ERR_UNAUTHORIZED")
    assert [o["loop_id"] for o in done["recovered"]] == ["loop-xrec-01"]
    assert after["ok"] is True and health_after == "ok"

    assert dispatch_cli(["validate-ring", "--grace", "0"], db_path=db).exit_code == EXIT_SUCCESS
    from aiosh_mcp import agent_loop_recovery as rec
    import datetime as dt
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=rec.MAX_TOTAL_TIMEOUT_S + 100)
    monkeypatch.setattr(rec, "_now", lambda: later)
    # A second crash, recovered through the CLI with the token from the environment.
    s = AgentLoopService(gate=PepCapabilityGate(db))
    mint_grant(db, "gr_xrun2", tools=["aios.agent_loop.start"])
    s.start_loop(LoopConfig(loop_id="loop-xrec-02"), capability_token="gr_xrun2")
    del s
    assert dispatch_cli(["validate-ring", "--grace", "0"], db_path=db).exit_code == EXIT_FAILURE
    mint_grant(db, "gr_xrecover2", tools=["aios.agent_loop.recover"])
    monkeypatch.setenv("AIOS_RECOVER_GRANT", "gr_xrecover2")
    out = dispatch_cli(["recover", "--token-env", "AIOS_RECOVER_GRANT", "--grace", "0", "--json"], db_path=db)
    assert out.exit_code == EXIT_SUCCESS and [o["loop_id"] for o in out.data["recovered"]] == ["loop-xrec-02"]


def test_metrics_health_degrades_on_orphans_past_grace(tmp_path, monkeypatch):
    """Past the grace period an orphan degrades health (checked in-process with a 0 s grace)."""
    from aiosh_mcp import agent_loop_recovery as rec
    from aiosh_mcp.agent_loop_observability import health, ring_metrics
    db = str(tmp_path / "audit.db")
    mint_grant(db, "gr_hrun", tools=["aios.agent_loop.start"])
    s = AgentLoopService(gate=PepCapabilityGate(db))
    s.start_loop(LoopConfig(loop_id="loop-xrec-h1"), capability_token="gr_hrun")
    del s
    import datetime as dt
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=rec.MAX_TOTAL_TIMEOUT_S + 100)
    monkeypatch.setattr(rec, "_now", lambda: later)
    ring = ring_metrics(db)
    ring["orphaned_runs"] = len(rec.validate_ring(db, 0)["orphaned"])
    assert ring["orphaned_runs"] == 1 and health(ring) == "degraded"
