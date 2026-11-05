"""Hardening tests for agent-loop observability (T-03340)."""

import logging
from contextlib import closing

import pytest

from agent_loop_grants import AllowAllGate
from aiosh_mcp import agent_loop_observability as obs
from aiosh_mcp import audit_client
from aiosh_mcp.agent_loop_data_model import LoopConfig
from aiosh_mcp.agent_loop_service import AgentLoopService


@pytest.fixture(scope="module")
def big_ring(tmp_path_factory):
    db = str(tmp_path_factory.mktemp("obs-hard") / "audit.db")
    with closing(audit_client.open_db(db)) as conn:
        conn.execute("BEGIN")
        for i in range(20_000):
            audit_client._insert_audit_row(conn, {
                "ts": audit_client.utcnow_iso(), "actor": "agent", "actor_id": obs.TRUSTED_ACTOR_ID,
                "tool": "aios.agent_loop.step", "command": "x",
                "args": {"loop_id": "l", "irreversible": "False", "duration_ms": str(i % 50)},
                "target": None, "outcome": "ok" if i % 3 else "refused",
                "outcome_detail": None if i % 3 else "LOOPSERV_ERR_POLICY_REFUSED: Policy evaluation refused tool invocation: caller policy verdict",
                "constitution_rev": None, "grant_token": None,
                "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True}})
        conn.commit()
    return db


def test_deadline_aborts_inside_sqlite(big_ring):
    with pytest.raises(obs.ObservabilityReadError) as exc:
        obs.ring_metrics(big_ring, 20_000, deadline_s=0.0)
    assert "budget" in str(exc.value) and obs.LOOPOBS_ERR_READ in str(exc.value)


def test_streamed_results_are_exact(big_ring):
    m = obs.ring_metrics(big_ring, 20_000)
    assert m["window"]["rows"] == 20_000 and m["window"]["last_id"] - m["window"]["first_id"] == 19_999
    assert m["steps"]["ok"] + m["steps"]["refused"] == 20_000
    assert m["refusals"]["caller"] == m["steps"]["refused"]
    assert m["steps"]["duration_ms"]["max"] == 49.0
    newest = obs.ring_metrics(big_ring, 10)["window"]
    assert newest["last_id"] == m["window"]["last_id"] and newest["rows"] == 10


def test_broken_log_handler_never_breaks_a_step():
    class Exploding(logging.Handler):
        def emit(self, record):
            raise RuntimeError("log sink down")

        def handleError(self, record):   # re-raise instead of printing, to prove log_event contains it
            raise RuntimeError("log sink down")

    h = Exploding()
    obs.logger.addHandler(h)
    old = obs.logger.level
    obs.logger.setLevel(logging.INFO)
    try:
        svc = AgentLoopService(gate=AllowAllGate())
        svc.start_loop(LoopConfig(loop_id="loop-obs-hard-1"), capability_token="t")
        assert svc.advance_turn("loop-obs-hard-1", "x", capability_token="t").outcome == "ok"
        assert svc.complete_loop("loop-obs-hard-1", capability_token="t").current_state.value == "COMPLETED"
    finally:
        obs.logger.removeHandler(h)
        obs.logger.setLevel(old)
