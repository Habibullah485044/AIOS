"""Unit tests for the Agent Loop Hardening MCP/API surface (T-03297).

Valid input, schema boundaries (both sides), invalid input and the primary failure
modes, asserted through tool results and audit-ring contents.
"""

import json

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from agent_loop_grants import audit_tools, mint_grant
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_mcp import register_agent_loop_mcp_tools
from aiosh_mcp.agent_loop_service import AgentLoopService

TOK = "gr_mcp_unit"


@pytest.fixture
def env(tmp_path):
    db = str(tmp_path / "audit.db")
    for i in range(4):
        mint_grant(db, f"{TOK}{i}", tools=["aios.agent_loop.start", "aios.fs.*"])
    app = FastMCP("agent-loop-unit")
    register_agent_loop_mcp_tools(app, service=AgentLoopService(gate=PepCapabilityGate(db)), db_path=db)
    return app, db


async def call(app, name, args):
    res = await app._tool_manager.call_tool(name, args)
    if isinstance(res, tuple):
        res = res[0]
    return json.loads(res[0].text) if isinstance(res, list) else res


async def started(app, lid="loop-mcp-unit-01", tok=f"{TOK}0"):
    out = await call(app, "aios_agent_loop_start", {"loop_id": lid, "capability_token": tok})
    assert out["ok"], out
    return lid, tok


# ---- schema boundaries: accepted edges --------------------------------------

@pytest.mark.anyio
@pytest.mark.parametrize("lid", ["a" * 8, "b" * 64])
async def test_loop_id_length_edges_accepted(env, lid):
    app, _ = env
    assert (await call(app, "aios_agent_loop_start", {"loop_id": lid, "capability_token": f"{TOK}0"}))["ok"]


@pytest.mark.anyio
async def test_turn_field_edges_accepted(env):
    app, _ = env
    lid, tok = await started(app)
    out = await call(app, "aios_agent_loop_advance", {
        "loop_id": lid, "capability_token": tok, "action_intent": "x" * 4096,
        "tool_name": "a" * 128, "tokens_consumed": 0})
    assert out["ok"]
    out = await call(app, "aios_agent_loop_abort", {"loop_id": lid, "capability_token": tok, "reason": "r" * 1024})
    assert out["ok"]
    for limit in (1, 1000):
        assert (await call(app, "aios_agent_loop_history", {"loop_id": lid, "limit": limit}))["ok"]


# ---- schema boundaries: rejected one step past the edge ---------------------

@pytest.mark.anyio
@pytest.mark.parametrize("tool,args", [
    ("aios_agent_loop_start", {"loop_id": "a" * 7}),
    ("aios_agent_loop_start", {"loop_id": "b" * 65}),
    ("aios_agent_loop_start", {"loop_id": "loop-mcp-unit-xx", "capability_token": "t" * 257}),
    ("aios_agent_loop_start", {"loop_id": "loop-mcp-unit-xx", "max_iterations": 101}),
    ("aios_agent_loop_start", {"loop_id": "loop-mcp-unit-xx", "total_timeout_ms": 4999}),
    ("aios_agent_loop_advance", {"loop_id": "loop-mcp-unit-01", "action_intent": ""}),
    ("aios_agent_loop_advance", {"loop_id": "loop-mcp-unit-01", "action_intent": "x" * 4097}),
    ("aios_agent_loop_advance", {"loop_id": "loop-mcp-unit-01", "action_intent": "x", "tool_name": "a b"}),
    ("aios_agent_loop_advance", {"loop_id": "loop-mcp-unit-01", "action_intent": "x", "tokens_consumed": -1}),
    ("aios_agent_loop_advance", {"loop_id": "loop-mcp-unit-01", "action_intent": "x", "tokens_consumed": 1_000_001}),
    ("aios_agent_loop_abort", {"loop_id": "loop-mcp-unit-01", "reason": "r" * 1025}),
    ("aios_agent_loop_history", {"loop_id": "loop-mcp-unit-01", "limit": 0}),
    ("aios_agent_loop_history", {"loop_id": "loop-mcp-unit-01", "limit": 1001}),
])
async def test_schema_violations_rejected_before_any_write(env, tool, args):
    app, db = env
    with pytest.raises(ToolError):
        await call(app, tool, args)
    assert audit_tools(db) == []


# ---- invalid input that passes the schema ------------------------------------

@pytest.mark.anyio
async def test_missing_token_is_unauthorized_envelope(env):
    app, db = env
    out = await call(app, "aios_agent_loop_start", {"loop_id": "loop-mcp-unit-02"})
    assert (out["ok"], out["error_code"]) == (False, "LOOPSERV_ERR_UNAUTHORIZED")
    assert audit_tools(db) == []


@pytest.mark.anyio
async def test_unknown_loop_not_found(env):
    app, _ = env
    for tool, extra in [("aios_agent_loop_snapshot", {}),
                        ("aios_agent_loop_advance", {"action_intent": "x", "capability_token": "t"}),
                        ("aios_agent_loop_complete", {"capability_token": "t"})]:
        out = await call(app, tool, {"loop_id": "loop-mcp-missing", **extra})
        assert out["error_code"] == "LOOPSERV_ERR_NOT_FOUND"


# ---- primary failure modes ----------------------------------------------------

@pytest.mark.anyio
async def test_complete_twice_and_abort_idempotent(env):
    app, _ = env
    lid, tok = await started(app)
    assert (await call(app, "aios_agent_loop_complete", {"loop_id": lid, "capability_token": tok}))["ok"]
    again = await call(app, "aios_agent_loop_complete", {"loop_id": lid, "capability_token": tok})
    assert again["error_code"] == "LOOPSERV_ERR_TERMINATED"
    a1 = await call(app, "aios_agent_loop_abort", {"loop_id": lid, "reason": "x", "capability_token": tok})
    assert a1["ok"] and a1["data"]["snapshot"]["current_state"] == "COMPLETED"


@pytest.mark.anyio
async def test_wrong_loop_token_unauthorized(env):
    app, _ = env
    lid, _ = await started(app)
    await started(app, "loop-mcp-unit-other", f"{TOK}1")
    out = await call(app, "aios_agent_loop_complete", {"loop_id": lid, "capability_token": f"{TOK}1"})
    assert out["error_code"] == "LOOPSERV_ERR_UNAUTHORIZED"


@pytest.mark.anyio
async def test_read_only_tools_write_nothing(env):
    app, db = env
    lid, tok = await started(app)
    before = audit_tools(db)
    await call(app, "aios_agent_loop_snapshot", {"loop_id": lid})
    await call(app, "aios_agent_loop_list", {"include_terminated": True})
    await call(app, "aios_agent_loop_history", {"loop_id": lid})
    assert audit_tools(db) == before


@pytest.mark.anyio
async def test_history_corrupt_db_is_explicit_error(tmp_path):
    bad = tmp_path / "corrupt.db"
    bad.write_bytes(b"not sqlite" * 200)
    app = FastMCP("agent-loop-unit-corrupt")
    register_agent_loop_mcp_tools(app, service=AgentLoopService(gate=PepCapabilityGate(str(bad))), db_path=str(bad))
    out = await call(app, "aios_agent_loop_history", {"loop_id": "loop-mcp-unit-01"})
    assert (out["ok"], out["error_code"]) == (False, "LOOPMCP_ERR_AUDIT_READ")


@pytest.mark.anyio
async def test_history_missing_db_empty(tmp_path):
    app = FastMCP("agent-loop-unit-missing")
    missing = str(tmp_path / "none" / "audit.db")
    register_agent_loop_mcp_tools(app, service=AgentLoopService(gate=PepCapabilityGate(missing)), db_path=missing)
    out = await call(app, "aios_agent_loop_history", {"loop_id": "loop-mcp-unit-01"})
    assert out == {"ok": True, "data": {"loop_id": "loop-mcp-unit-01", "events": []}}
