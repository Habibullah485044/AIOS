"""Security tests for the Agent Loop Hardening MCP/API surface (T-03299).

One test per abuse scenario in docs/tasks/evidence/T-03299-security.md.
"""

import json
import sqlite3

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

from agent_loop_grants import audit_tools, mint_grant
from aiosh_mcp.agent_loop_data_model import MAX_ARGS_SUMMARY_BYTES
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_mcp import TOOL_ANNOTATIONS, register_agent_loop_mcp_tools
from aiosh_mcp.agent_loop_service import AgentLoopService

TOK = "gr_mcp_sec"


@pytest.fixture
def env(tmp_path):
    db = str(tmp_path / "audit.db")
    mint_grant(db, TOK, tools=["aios.agent_loop.start", "aios.fs.read"])
    mint_grant(db, TOK + "_b", tools=["aios.agent_loop.start", "aios.fs.read"])
    app = FastMCP("agent-loop-sec")
    register_agent_loop_mcp_tools(app, service=AgentLoopService(gate=PepCapabilityGate(db)), db_path=db)
    return app, db


async def call(app, name, args):
    res = await app._tool_manager.call_tool(name, args)
    if isinstance(res, tuple):
        res = res[0]
    return json.loads(res[0].text) if isinstance(res, list) else res


async def start(app, lid="loop-mcp-sec-01", tok=TOK):
    out = await call(app, "aios_agent_loop_start", {"loop_id": lid, "capability_token": tok})
    assert out["ok"], out
    return lid


@pytest.mark.anyio
async def test_m2_oversized_args_rejected_not_truncated(env):
    """M2 (audit evasion): benign prefix + hidden payload past the 64 KiB cut is refused, nothing recorded."""
    app, db = env
    lid = await start(app)
    rows_before = audit_tools(db)
    payload = {"path": "README.md", "pad": "x" * MAX_ARGS_SUMMARY_BYTES, "hidden": "rm -rf /"}
    out = await call(app, "aios_agent_loop_advance", {"loop_id": lid, "action_intent": "read",
                                                      "tool_name": "aios.fs.read", "tool_args": payload,
                                                      "capability_token": TOK})
    assert (out["ok"], out["error_code"]) == (False, "LOOPSERV_ERR_INVALID_INPUT")
    assert audit_tools(db) == rows_before
    snap = await call(app, "aios_agent_loop_snapshot", {"loop_id": lid})
    assert snap["data"]["snapshot"]["steps"] == []


@pytest.mark.anyio
async def test_m2_args_under_cap_are_audited_in_full(env):
    app, db = env
    lid = await start(app)
    payload = {"path": "README.md", "tail_marker": "END-OF-ARGS"}
    out = await call(app, "aios_agent_loop_advance", {"loop_id": lid, "action_intent": "read",
                                                      "tool_name": "aios.fs.read", "tool_args": payload,
                                                      "capability_token": TOK})
    assert out["ok"]
    raw = sqlite3.connect(db).execute(
        "SELECT args_json FROM audit_ring WHERE tool='aios.agent_loop.step'").fetchone()[0]
    assert "END-OF-ARGS" in raw and "[TRUNCATED]" not in raw


@pytest.mark.anyio
async def test_m3_hostile_nesting_rejected(env):
    app, _ = env
    lid = await start(app)
    deep = cur = {}
    for _ in range(5000):
        cur["a"] = {}
        cur = cur["a"]
    out = await call(app, "aios_agent_loop_advance", {"loop_id": lid, "action_intent": "x",
                                                      "tool_args": deep, "capability_token": TOK})
    assert out["error_code"] == "LOOPSERV_ERR_INVALID_INPUT"
    assert "nested deeper" in out["error"]


@pytest.mark.anyio
async def test_m4_forged_and_cross_loop_tokens_refused(env):
    app, db = env
    out = await call(app, "aios_agent_loop_start", {"loop_id": "loop-mcp-sec-forge", "capability_token": "gr_forged"})
    assert out["error_code"] == "LOOPSERV_ERR_UNAUTHORIZED"
    lid = await start(app)
    await start(app, "loop-mcp-sec-other", TOK + "_b")
    for tool, extra in [("aios_agent_loop_advance", {"action_intent": "x"}),
                        ("aios_agent_loop_abort", {"reason": "hijack"}),
                        ("aios_agent_loop_complete", {})]:
        out = await call(app, tool, {"loop_id": lid, "capability_token": TOK + "_b", **extra})
        assert out["error_code"] == "LOOPSERV_ERR_UNAUTHORIZED", tool
    assert (await call(app, "aios_agent_loop_snapshot", {"loop_id": lid}))["data"]["snapshot"]["current_state"] == "OBSERVE"


@pytest.mark.anyio
async def test_m5_self_approved_out_of_scope_tool_refused(env):
    app, _ = env
    lid = await start(app)
    out = await call(app, "aios_agent_loop_advance", {"loop_id": lid, "action_intent": "w", "tool_name": "fs.write",
                                                      "policy_allowed": True, "capability_token": TOK})
    assert out["data"]["step"]["outcome"] == "refused"


@pytest.mark.anyio
async def test_m6_read_only_annotations_are_truthful(env):
    """Clients may auto-approve readOnlyHint tools, so they must not change state or the ring."""
    app, db = env
    lid = await start(app)
    rows, state = audit_tools(db), (await call(app, "aios_agent_loop_snapshot", {"loop_id": lid}))["data"]
    for name, ann in TOOL_ANNOTATIONS.items():
        if not ann.readOnlyHint:
            continue
        args = {} if name == "aios_agent_loop_list" else {"loop_id": lid}
        await call(app, name, args)
    assert audit_tools(db) == rows
    assert (await call(app, "aios_agent_loop_snapshot", {"loop_id": lid}))["data"] == state


@pytest.mark.anyio
async def test_m1_token_never_in_success_or_service_error_envelopes(env):
    app, _ = env
    lid = await start(app)
    outs = [await call(app, "aios_agent_loop_advance", {"loop_id": lid, "action_intent": "x", "capability_token": TOK}),
            await call(app, "aios_agent_loop_advance", {"loop_id": lid, "action_intent": "x",
                                                        "capability_token": "gr_mcp_sec_wrong"}),
            await call(app, "aios_agent_loop_history", {"loop_id": lid})]
    for out in outs:
        dumped = json.dumps(out)
        assert TOK not in dumped and "gr_mcp_sec_wrong" not in dumped


@pytest.mark.anyio
async def test_m7_secrets_masked_in_snapshot_and_history(env):
    app, _ = env
    lid = await start(app)
    await call(app, "aios_agent_loop_advance", {"loop_id": lid, "action_intent": "x", "tool_name": "aios.fs.read",
                                                "tool_args": {"auth": "Bearer sk-abcdefghijklmnopqrstuvwxyz0123"},
                                                "capability_token": TOK})
    for name in ("aios_agent_loop_snapshot", "aios_agent_loop_history"):
        assert "sk-abcdefghijklmnop" not in json.dumps(await call(app, name, {"loop_id": lid}))


@pytest.mark.anyio
async def test_m8_schema_rejects_injection_shaped_ids(env):
    app, db = env
    with pytest.raises(ToolError):
        await call(app, "aios_agent_loop_history", {"loop_id": "x' OR '1'='1"})
    assert audit_tools(db) == []
