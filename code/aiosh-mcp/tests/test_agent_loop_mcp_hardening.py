"""Hardening tests for the Agent Loop Hardening MCP/API surface (T-03300)."""

import json
import time

import anyio
import pytest
from mcp.server.fastmcp import FastMCP

from agent_loop_grants import AllowAllGate, mint_grant
from aiosh_mcp import agent_loop_mcp
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_mcp import register_agent_loop_mcp_tools
from aiosh_mcp.agent_loop_service import AgentLoopService


async def call(app, name, args):
    res = await app._tool_manager.call_tool(name, args)
    if isinstance(res, tuple):
        res = res[0]
    return json.loads(res[0].text) if isinstance(res, list) else res


class SlowAuditGate(AllowAllGate):
    """Simulates a locked audit DB: every audit write blocks for `delay` seconds."""

    def __init__(self, delay):
        super().__init__()
        self.delay = delay

    def audit(self, *a, **k):
        time.sleep(self.delay)
        super().audit(*a, **k)


@pytest.mark.anyio
async def test_blocking_call_does_not_stall_other_requests(monkeypatch):
    """A slow mutating call runs off the event loop: a read-only call completes meanwhile."""
    app = FastMCP("hard-offload")
    svc = AgentLoopService(gate=AllowAllGate())
    register_agent_loop_mcp_tools(app, service=svc)
    await call(app, "aios_agent_loop_start", {"loop_id": "loop-mcp-hard-fast", "capability_token": "t"})
    svc._gate = SlowAuditGate(1.0)
    done = {}

    async def slow():
        done["slow"] = await call(app, "aios_agent_loop_advance",
                                  {"loop_id": "loop-mcp-hard-fast", "action_intent": "x", "capability_token": "t"})
        done["slow_t"] = time.monotonic()

    async def fast():
        await anyio.sleep(0.1)
        done["fast"] = await call(app, "aios_agent_loop_list", {})
        done["fast_t"] = time.monotonic()

    async with anyio.create_task_group() as tg:
        tg.start_soon(slow)
        tg.start_soon(fast)
    assert done["slow"]["ok"] and done["fast"]["ok"]
    assert done["fast_t"] < done["slow_t"]


@pytest.mark.anyio
async def test_timeout_returns_explicit_envelope(monkeypatch):
    app = FastMCP("hard-timeout")
    svc = AgentLoopService(gate=AllowAllGate())
    register_agent_loop_mcp_tools(app, service=svc, settings={"mcp_call_timeout_s": 0.3})
    await call(app, "aios_agent_loop_start", {"loop_id": "loop-mcp-hard-tmo", "capability_token": "t"})
    svc._gate = SlowAuditGate(1.0)
    out = await call(app, "aios_agent_loop_advance",
                     {"loop_id": "loop-mcp-hard-tmo", "action_intent": "x", "capability_token": "t"})
    assert (out["ok"], out["error_code"]) == (False, "LOOPMCP_ERR_TIMEOUT")
    assert "outcome unknown" in out["error"]


@pytest.mark.anyio
async def test_history_pages_within_budget(tmp_path, monkeypatch):
    db = str(tmp_path / "audit.db")
    mint_grant(db, "gr_mcp_hard", tools=["aios.agent_loop.start", "aios.fs.read"])
    app = FastMCP("hard-page")
    register_agent_loop_mcp_tools(app, service=AgentLoopService(gate=PepCapabilityGate(db)), db_path=db,
                                  settings={"history_page_bytes": 2000})
    lid = "loop-mcp-hard-page"
    await call(app, "aios_agent_loop_start", {"loop_id": lid, "capability_token": "gr_mcp_hard"})
    for i in range(12):
        await call(app, "aios_agent_loop_advance", {"loop_id": lid, "action_intent": "x", "tool_name": "aios.fs.read",
                                                    "tool_args": {"i": i, "pad": "p" * 100},
                                                    "capability_token": "gr_mcp_hard"})
    seen, after, pages = [], 0, 0
    while True:
        page = (await call(app, "aios_agent_loop_history", {"loop_id": lid, "after_id": after}))["data"]
        pages += 1
        assert len(json.dumps(page["events"])) <= 2000 + 600  # whole events only; one may straddle the budget
        seen += page["events"]
        if not page["truncated"]:
            break
        after = page["next_after_id"]
    assert pages > 1
    assert [e["id"] for e in seen] == sorted({e["id"] for e in seen})
    assert len(seen) == 13  # start + 12 steps, no gaps or duplicates across pages


@pytest.mark.anyio
async def test_snapshot_steps_tail_bounds_response():
    app = FastMCP("hard-tail")
    register_agent_loop_mcp_tools(app, service=AgentLoopService(gate=AllowAllGate()))
    lid = "loop-mcp-hard-tail"
    await call(app, "aios_agent_loop_start", {"loop_id": lid, "capability_token": "t", "max_iterations": 50})
    for _ in range(30):
        await call(app, "aios_agent_loop_advance", {"loop_id": lid, "action_intent": "x", "capability_token": "t"})
    out = (await call(app, "aios_agent_loop_snapshot", {"loop_id": lid, "steps_tail": 5}))["data"]
    assert out["steps_total"] == 30
    assert [s["step_index"] for s in out["snapshot"]["steps"]] == [25, 26, 27, 28, 29]
    none = (await call(app, "aios_agent_loop_snapshot", {"loop_id": lid, "steps_tail": 0}))["data"]
    assert none["snapshot"]["steps"] == [] and none["steps_total"] == 30
