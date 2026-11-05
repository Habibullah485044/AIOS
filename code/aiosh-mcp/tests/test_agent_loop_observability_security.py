"""Security regression tests for agent-loop observability (T-03339).

Each case replays a finding from the independent review of T-03336..T-03338.
"""

import json
import logging
from contextlib import closing

import pytest
from mcp.server.fastmcp import FastMCP

from agent_loop_grants import mint_grant, revoke_grant
from aiosh_mcp import agent_loop_observability as obs
from aiosh_mcp import audit_client
from aiosh_mcp.agent_loop_data_model import LoopConfig
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_mcp import register_agent_loop_mcp_tools
from aiosh_mcp.agent_loop_service import AgentLoopService

GRANT = "gr_SECRETbearer01"
SCOPE = {"tools": ["aios.agent_loop.start", "aios.fs.*"], "paths": {"allow": ["/tmp"], "deny": []}}


@pytest.fixture
def env(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="aiosh_mcp.agent_loop")
    db = str(tmp_path / "audit.db")
    mint_grant(db, GRANT)
    with closing(audit_client.open_db(db)) as conn:
        conn.execute("UPDATE pep_grants SET scope_json=? WHERE grant_id=?", (json.dumps(SCOPE), GRANT))
        conn.commit()
    svc = AgentLoopService(gate=PepCapabilityGate(db))
    svc.start_loop(LoopConfig(loop_id="loop-osec-01", max_iterations=30), capability_token=GRANT)
    return svc, db, caplog


def logged(caplog):
    return "\n".join(r.getMessage() + json.dumps(getattr(r, "agent_loop", {})) for r in caplog.records)


def test_f1_revoked_grant_id_never_logged(env):
    svc, _, caplog = env
    revoke_grant(svc._gate._db_path, GRANT)
    s = svc.advance_turn("loop-osec-01", "x", tool_name="aios.fs.read", tool_args={"path": "/tmp/a"},
                         capability_token=GRANT)
    assert s.outcome == "refused" and GRANT in s.error_message      # the caller still sees why
    assert GRANT not in logged(caplog)
    assert caplog.records[-1].agent_loop["reason"] == "scope"


def test_f1_targets_never_logged(env):
    svc, _, caplog = env
    svc.advance_turn("loop-osec-01", "x", tool_name="aios.fs.read", tool_args={"path": "/etc/very-private-name"},
                     capability_token=GRANT)
    assert "very-private-name" not in logged(caplog)


def test_f2_no_log_injection(env):
    svc, _, caplog = env
    evil = "/tmp/../x\nINFO agent_loop step loop=FAKE outcome=ok"
    svc.advance_turn("loop-osec-01", "x", tool_name="aios.fs.read", tool_args={"path": evil}, capability_token=GRANT)
    assert all("\n" not in r.getMessage() for r in caplog.records)
    assert "loop=FAKE" not in logged(caplog)


@pytest.mark.parametrize("path", ["/x/GATE_UNAVAILABLE", "/x/LOOPPOL_ERR_CONSTITUTION", "/x/LOOPPOL_ERR_IRREVERSIBLE_BUDGET"])
def test_f2_codes_in_targets_cannot_spoof_counters_or_health(env, path):
    svc, db, _ = env
    s = svc.advance_turn("loop-osec-01", "x", tool_name="aios.fs.read", tool_args={"path": path},
                         capability_token=GRANT)
    assert s.outcome == "refused" and s.policy["refusal_reason"] == "scope"
    st = svc.stats()["counters"]
    assert (st["gate_unavailable"], st["budget_refusals"]) == (0, 0)
    m = obs.ring_metrics(db)
    assert m["refusals"]["scope"] == 1 and m["refusals"]["gate_unavailable"] == 0
    assert obs.health(m, svc.stats()) == "ok"


def _forge(db, n):
    with closing(audit_client.open_db(db)) as conn:
        for _ in range(n):
            audit_client.write_audit_row(conn, {
                "ts": audit_client.utcnow_iso(), "actor": "agent", "actor_id": "agent:forger", "tool": "aios.agent_loop.step",
                "command": "x", "args": {"loop_id": "loop-osec-01", "irreversible": "True", "duration_ms": "0.001"},
                "target": None, "outcome": "ok", "outcome_detail": None, "constitution_rev": None,
                "grant_token": "gr_victim", "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True}})


def test_f3_forged_rows_are_not_counted(env):
    svc, db, _ = env
    _forge(db, 25)
    m = obs.ring_metrics(db)
    assert m["steps"]["ok"] == 0 and m["steps"]["irreversible_ok"] == 0 and m["irreversible_by_grant"] == []


@pytest.mark.anyio
async def test_f3_small_window_cannot_hide_degradation(env):
    svc, db, _ = env
    with closing(audit_client.open_db(db)) as conn:   # a real degraded-config row from the gate's actor
        audit_client.write_audit_row(conn, {
            "ts": audit_client.utcnow_iso(), "actor": "agent", "actor_id": obs.TRUSTED_ACTOR_ID,
            "tool": "aios.agent_loop.config", "command": "c", "args": {}, "target": None, "outcome": "degraded",
            "outcome_detail": "x", "constitution_rev": None, "grant_token": None,
            "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True}})
    for _ in range(5):
        svc.advance_turn("loop-osec-01", "x", capability_token=GRANT)
    app = FastMCP("osec")
    register_agent_loop_mcp_tools(app, service=svc, db_path=db, settings={})
    res = await app._tool_manager.call_tool("aios_agent_loop_metrics", {"window": 2})
    res = res[0] if isinstance(res, tuple) else res
    data = json.loads(res[0].text)["data"] if isinstance(res, list) else res["data"]
    assert data["ring"]["degraded_config_rows"] == 0          # outside the caller's window...
    assert data["health"] == "degraded"                       # ...but health uses the fixed default window
