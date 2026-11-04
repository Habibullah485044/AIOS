"""Integration tests for Agent Loop Hardening Core Service (T-03278).

Drives the service through its production surface (FastMCP tools registered in
server.py) and checks canonical-JSON parity of the snapshots it returns.
"""

import json

import pytest

from agent_loop_grants import mint_grant
from aiosh_mcp.server import mcp
from aiosh_mcp.agent_loop_data_model import LoopSnapshot
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_service import (
    LOOPSERV_ERR_NOT_FOUND,
    LOOPSERV_ERR_TERMINATED,
    LOOPSERV_ERR_UNAUTHORIZED,
    _GLOBAL_AGENT_LOOP_SERVICE,
)


def _reset() -> None:
    _GLOBAL_AGENT_LOOP_SERVICE._loops.clear()
    _GLOBAL_AGENT_LOOP_SERVICE._configs.clear()
    _GLOBAL_AGENT_LOOP_SERVICE._start_times.clear()
    _GLOBAL_AGENT_LOOP_SERVICE._grants.clear()


@pytest.fixture(autouse=True)
def clean_service(tmp_path, monkeypatch):
    """Isolated audit DB with a real PEP grant "tok" (T-03279: tokens are redeemed)."""
    db = str(tmp_path / "audit.db")
    mint_grant(db, "tok")
    monkeypatch.setattr(_GLOBAL_AGENT_LOOP_SERVICE, "_gate", PepCapabilityGate(db))
    _reset()
    yield
    _reset()


def _payload(res) -> dict:
    if isinstance(res, dict):
        return res
    if isinstance(res, tuple):
        return _payload(res[0])
    if isinstance(res, list) and res and hasattr(res[0], "text"):
        return json.loads(res[0].text)
    raise AssertionError(f"unexpected tool result: {res!r}")


async def _call(name: str, args: dict) -> dict:
    return _payload(await mcp._tool_manager.call_tool(name, args))


def test_service_tools_registered():
    names = {t.name for t in mcp._tool_manager.list_tools()}
    assert {
        "aios_agent_loop_start",
        "aios_agent_loop_advance",
        "aios_agent_loop_abort",
        "aios_agent_loop_snapshot",
    } <= names


@pytest.mark.anyio
async def test_end_to_end_start_advance_abort():
    lid = "loop-integ-svc-01"
    started = await _call("aios_agent_loop_start", {"loop_id": lid, "capability_token": "tok"})
    assert started["ok"] is True
    assert started["data"]["snapshot"]["current_state"] == "OBSERVE"

    adv = await _call("aios_agent_loop_advance", {
        "loop_id": lid, "action_intent": "read", "tool_name": "aios.fs.read",
        "tool_args": {"path": "README.md"}, "tokens_consumed": 42, "capability_token": "tok",
    })
    assert adv["ok"] is True
    assert adv["data"]["step"]["outcome"] == "ok"
    assert adv["data"]["state"] == "OBSERVE"

    refused = await _call("aios_agent_loop_advance", {
        "loop_id": lid, "action_intent": "write", "tool_name": "fs.write",
        "policy_allowed": False, "capability_token": "tok",
    })
    assert refused["data"]["step"]["outcome"] == "refused"

    snap = await _call("aios_agent_loop_snapshot", {"loop_id": lid})
    assert snap["data"]["snapshot"]["total_tokens_used"] == 42
    assert len(snap["data"]["snapshot"]["steps"]) == 2

    aborted = await _call("aios_agent_loop_abort", {"loop_id": lid, "reason": "done", "capability_token": "tok"})
    assert aborted["data"]["snapshot"]["current_state"] == "ABORTED"

    after = await _call("aios_agent_loop_advance", {"loop_id": lid, "action_intent": "x", "capability_token": "tok"})
    assert after["ok"] is False
    assert after["error_code"] == LOOPSERV_ERR_TERMINATED


@pytest.mark.anyio
async def test_mutating_tools_fail_closed_without_token():
    res = await _call("aios_agent_loop_start", {"loop_id": "loop-integ-svc-02"})
    assert res["ok"] is False
    assert res["error_code"] == LOOPSERV_ERR_UNAUTHORIZED
    missing = await _call("aios_agent_loop_snapshot", {"loop_id": "loop-integ-svc-02"})
    assert missing["error_code"] == LOOPSERV_ERR_NOT_FOUND


@pytest.mark.anyio
async def test_invalid_config_returns_envelope_not_exception():
    res = await _call("aios_agent_loop_start", {"loop_id": "bad", "capability_token": "tok"})
    assert res["ok"] is False
    assert res["error_code"] == "LOOPDATA_ERR_BOUNDS_EXCEEDED"


@pytest.mark.anyio
async def test_snapshot_canonical_json_round_trip():
    lid = "loop-integ-svc-03"
    await _call("aios_agent_loop_start", {"loop_id": lid, "capability_token": "tok"})
    await _call("aios_agent_loop_advance", {
        "loop_id": lid, "action_intent": "a", "tokens_consumed": 7, "capability_token": "tok",
    })
    snap = (await _call("aios_agent_loop_snapshot", {"loop_id": lid}))["data"]["snapshot"]
    canonical = json.dumps(snap, sort_keys=True, separators=(",", ":"))
    restored = LoopSnapshot.from_dict(json.loads(canonical))
    assert json.dumps(restored.to_dict(), sort_keys=True, separators=(",", ":")) == canonical
