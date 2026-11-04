"""Regression tests for security audit findings #2, #4 and #5 (2026-11-05).

#2 history injection via an aliased or reused loop_id; #4 init shadowing a live
loop's status; #5 complete skipping grant-liveness and timeout checks.
"""

import json
import time

import pytest

from agent_loop_grants import mint_grant, revoke_grant
from aiosh_mcp.agent_loop_cli import dispatch_cli
from aiosh_mcp.agent_loop_data_model import LoopConfig, LoopState
from aiosh_mcp.agent_loop_gate import PepCapabilityGate, read_loop_history
from aiosh_mcp.agent_loop_service import (
    AgentLoopService,
    AgentLoopServiceError,
    LOOPSERV_ERR_ALREADY_EXISTS,
    LOOPSERV_ERR_TIMEOUT,
    LOOPSERV_ERR_UNAUTHORIZED,
)

SCOPE = ["aios.agent_loop.start", "aios.fs.read"]


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "audit.db")
    for gid in ("gr_victim", "gr_attacker", "gr_attacker2"):
        mint_grant(path, gid, tools=SCOPE)
    return path


def test_aliased_loop_id_is_rejected(db):
    """'victim01 ' used to be stripped into 'victim01' for some rows but not others."""
    svc = AgentLoopService(gate=PepCapabilityGate(db))
    for alias in ("loop-victim-01 ", " loop-victim-01", "loop-victim-01\n"):
        with pytest.raises(ValueError):
            svc.start_loop(LoopConfig(loop_id=alias), capability_token="gr_attacker")


def test_second_process_cannot_reuse_a_started_loop_id(db):
    """A separate service (other process / after restart) cannot append to the victim's history."""
    victim = AgentLoopService(gate=PepCapabilityGate(db))
    victim.start_loop(LoopConfig(loop_id="loop-victim-01"), capability_token="gr_victim")
    victim.advance_turn("loop-victim-01", "read", tool_name="aios.fs.read", capability_token="gr_victim")

    attacker = AgentLoopService(gate=PepCapabilityGate(db))
    with pytest.raises(AgentLoopServiceError) as exc:
        attacker.start_loop(LoopConfig(loop_id="loop-victim-01"), capability_token="gr_attacker")
    assert exc.value.code == LOOPSERV_ERR_ALREADY_EXISTS

    # The refused attempt did not burn the attacker's grant (checked before redemption)...
    attacker.start_loop(LoopConfig(loop_id="loop-attacker-01"), capability_token="gr_attacker")
    # ...and the victim's history contains only the victim's run.
    events = read_loop_history(db, "loop-victim-01", 100)
    assert [e["tool"] for e in events] == ["aios.agent_loop.start", "aios.agent_loop.step"]
    assert len({e["args"]["run_id"] for e in events}) == 1


def test_cli_cannot_reuse_a_started_loop_id(db, tmp_path):
    AgentLoopService(gate=PepCapabilityGate(db)).start_loop(
        LoopConfig(loop_id="loop-victim-02"), capability_token="gr_victim")
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"turns": [{"action_intent": "x", "tool_name": "aios.fs.read",
                                           "tool_args": {"forged": "rm -rf /"}}]}), encoding="utf-8")
    res = dispatch_cli(["run", "--loop-id", "loop-victim-02", "--token", "gr_attacker", "--plan", str(plan)],
                       service=AgentLoopService(gate=PepCapabilityGate(db)), db_path=db)
    assert res.error_code == LOOPSERV_ERR_ALREADY_EXISTS
    assert all("forged" not in json.dumps(e) for e in read_loop_history(db, "loop-victim-02", 100))


def test_concurrent_start_race_has_one_winner(db):
    """Both services pass the pre-check; the atomic claim in the start row lets only one register."""
    a = AgentLoopService(gate=PepCapabilityGate(db))
    b = AgentLoopService(gate=PepCapabilityGate(db))
    b._gate.loop_id_used = lambda loop_id: False  # simulate b's pre-check running before a's claim
    a.start_loop(LoopConfig(loop_id="loop-race-01"), capability_token="gr_victim")
    with pytest.raises(AgentLoopServiceError) as exc:
        b.start_loop(LoopConfig(loop_id="loop-race-01"), capability_token="gr_attacker")
    assert exc.value.code == LOOPSERV_ERR_ALREADY_EXISTS
    assert b.list_active_loops() == []
    starts = [e for e in read_loop_history(db, "loop-race-01", 100) if e["tool"] == "aios.agent_loop.start"]
    assert len(starts) == 1


def test_every_row_of_a_run_carries_its_run_id(db):
    svc = AgentLoopService(gate=PepCapabilityGate(db))
    svc.start_loop(LoopConfig(loop_id="loop-runid-01"), capability_token="gr_victim")
    svc.advance_turn("loop-runid-01", "x", tool_name="aios.fs.read", capability_token="gr_victim")
    svc.advance_turn("loop-runid-01", "y", tool_name="fs.write", capability_token="gr_victim")
    svc.complete_loop("loop-runid-01", capability_token="gr_victim")
    run_ids = {e["args"].get("run_id") for e in read_loop_history(db, "loop-runid-01", 100)}
    assert run_ids == {svc.run_id("loop-runid-01")}
    assert len(svc.run_id("loop-runid-01")) == 16


def test_complete_refused_after_revocation(db):
    svc = AgentLoopService(gate=PepCapabilityGate(db))
    svc.start_loop(LoopConfig(loop_id="loop-revoke-01"), capability_token="gr_victim")
    revoke_grant(db, "gr_victim")
    with pytest.raises(AgentLoopServiceError) as exc:
        svc.complete_loop("loop-revoke-01", capability_token="gr_victim")
    assert exc.value.code == LOOPSERV_ERR_UNAUTHORIZED
    # Stopping stays possible: abort is restraint, not new action.
    assert svc.abort_loop("loop-revoke-01", "revoked", capability_token="gr_victim").current_state == LoopState.ABORTED


def test_complete_after_timeout_aborts_as_timeout(db):
    svc = AgentLoopService(gate=PepCapabilityGate(db))
    svc.start_loop(LoopConfig(loop_id="loop-late-01", total_timeout_ms=5000.0), capability_token="gr_victim")
    svc._start_times["loop-late-01"] = time.time() - 10
    with pytest.raises(AgentLoopServiceError) as exc:
        svc.complete_loop("loop-late-01", capability_token="gr_victim")
    assert exc.value.code == LOOPSERV_ERR_TIMEOUT
    assert svc.get_snapshot("loop-late-01").current_state == LoopState.ABORTED
    assert [e["tool"] for e in read_loop_history(db, "loop-late-01", 100)][-1] == "aios.agent_loop.timeout"


@pytest.mark.anyio
async def test_init_cannot_shadow_a_running_loop(tmp_path, monkeypatch):
    from aiosh_mcp.agent_loop_data_model import _GLOBAL_LOOP_REGISTRY
    from aiosh_mcp.agent_loop_service import _GLOBAL_AGENT_LOOP_SERVICE
    from aiosh_mcp.server import mcp

    db = str(tmp_path / "audit.db")
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path))
    mint_grant(db, "gr_live", tools=SCOPE)
    mint_grant(db, "gr_shadow", tools=SCOPE)
    monkeypatch.setattr(_GLOBAL_AGENT_LOOP_SERVICE, "_gate", PepCapabilityGate(db))
    lid = "loop-shadow-01"
    try:
        _GLOBAL_AGENT_LOOP_SERVICE.start_loop(LoopConfig(loop_id=lid), capability_token="gr_live")
        _GLOBAL_AGENT_LOOP_SERVICE.advance_turn(lid, "x", capability_token="gr_live")

        def payload(res):
            res = res[0] if isinstance(res, tuple) else res
            return json.loads(res[0].text) if isinstance(res, list) else res

        init = payload(await mcp._tool_manager.call_tool(
            "aios_agent_loop_init", {"loop_id": lid, "capability_token": "gr_shadow"}))
        assert init["ok"] is False and "already exists" in init["error"]
        status = payload(await mcp._tool_manager.call_tool("aios_agent_loop_status", {"loop_id": lid}))
        assert status["snapshot"]["current_state"] == "OBSERVE"
        assert status["snapshot"]["current_iteration"] == 1
    finally:
        _GLOBAL_LOOP_REGISTRY.clear()
        for table in ("_loops", "_configs", "_start_times", "_grants", "_runs"):
            getattr(_GLOBAL_AGENT_LOOP_SERVICE, table).pop(lid, None)
