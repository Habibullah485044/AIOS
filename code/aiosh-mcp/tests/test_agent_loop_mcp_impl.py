"""Implementation tests for the Agent Loop Hardening MCP/API surface (T-03296)."""

import json

import pytest
from mcp.server.fastmcp import FastMCP

from agent_loop_grants import mint_grant
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_mcp import TOOL_ANNOTATIONS, register_agent_loop_mcp_tools
from aiosh_mcp.agent_loop_service import AgentLoopService


@pytest.fixture
def app(tmp_path):
    db = str(tmp_path / "audit.db")
    mint_grant(db, "gr_mcp_impl", tools=["aios.agent_loop.start", "aios.fs.read"])
    a = FastMCP("agent-loop-impl")
    register_agent_loop_mcp_tools(a, service=AgentLoopService(gate=PepCapabilityGate(db)), db_path=db)
    return a


async def call(app, name, args):
    res = await app._tool_manager.call_tool(name, args)
    if isinstance(res, tuple):
        res = res[0]
    if isinstance(res, list):
        return json.loads(res[0].text)
    return res


def test_seven_tools_with_annotations(app):
    tools = {t.name: t for t in app._tool_manager.list_tools()}
    assert set(tools) == set(TOOL_ANNOTATIONS)
    for name, ann in TOOL_ANNOTATIONS.items():
        assert tools[name].annotations == ann


@pytest.mark.anyio
async def test_lifecycle_complete_list_history(app):
    lid, tok = "loop-mcp-impl-01", "gr_mcp_impl"
    assert (await call(app, "aios_agent_loop_start", {"loop_id": lid, "capability_token": tok}))["ok"]
    adv = await call(app, "aios_agent_loop_advance", {"loop_id": lid, "action_intent": "read",
                                                      "tool_name": "aios.fs.read", "capability_token": tok})
    assert adv["data"]["step"]["outcome"] == "ok"
    listed = await call(app, "aios_agent_loop_list", {})
    assert [l["loop_id"] for l in listed["data"]["loops"]] == [lid]

    done = await call(app, "aios_agent_loop_complete", {"loop_id": lid, "capability_token": tok})
    assert done["data"]["snapshot"]["current_state"] == "COMPLETED"
    assert (await call(app, "aios_agent_loop_list", {}))["data"]["loops"] == []
    assert len((await call(app, "aios_agent_loop_list", {"include_terminated": True}))["data"]["loops"]) == 1

    hist = await call(app, "aios_agent_loop_history", {"loop_id": lid})
    assert [e["tool"] for e in hist["data"]["events"]] == [
        "aios.agent_loop.start", "aios.agent_loop.step", "aios.agent_loop.complete"]


@pytest.mark.anyio
async def test_responses_never_echo_token(app):
    lid, tok = "loop-mcp-impl-02", "gr_mcp_impl"
    outs = [await call(app, "aios_agent_loop_start", {"loop_id": lid, "capability_token": tok}),
            await call(app, "aios_agent_loop_advance", {"loop_id": lid, "action_intent": "x", "capability_token": tok}),
            await call(app, "aios_agent_loop_abort", {"loop_id": lid, "reason": "stop", "capability_token": tok}),
            await call(app, "aios_agent_loop_history", {"loop_id": lid})]
    for out in outs:
        assert "gr_mcp_impl" not in json.dumps(out)
