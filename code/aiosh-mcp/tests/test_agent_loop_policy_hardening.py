"""Hardening tests for the agent-loop security policy (T-03330).

The per-grant irreversible budget must hold under races: the budget check and the ok row
are one SQLite write transaction, so concurrent loops/processes cannot overspend it.
"""

import json
import multiprocessing as mp
import sqlite3
from contextlib import closing

from agent_loop_grants import mint_grant
from aiosh_mcp import audit_client
from aiosh_mcp.agent_loop_data_model import LoopConfig
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_service import AgentLoopService

SCOPE = {"tools": ["aios.agent_loop.start", "pentest.*"], "networks": ["10.0.0.0/24"]}


def shared_grant(db, gid, budget):
    mint_grant(db, gid, single_use=False)
    with closing(audit_client.open_db(db)) as conn:
        conn.execute("UPDATE pep_grants SET scope_json=? WHERE grant_id=?",
                     (json.dumps({**SCOPE, "max_irreversible": budget}), gid))
        conn.commit()


def ok_irreversible(db, gid):
    with closing(sqlite3.connect(db)) as conn:
        return conn.execute("SELECT count(*) FROM audit_ring WHERE tool='aios.agent_loop.step' AND outcome='ok' "
                            "AND grant_token=? AND json_extract(args_json,'$.irreversible')='True'", (gid,)).fetchone()[0]


def test_stale_precheck_is_caught_by_the_atomic_guard(tmp_path):
    """Service B's pre-check sees a stale count (as in a race); the guarded write still refuses."""
    db = str(tmp_path / "audit.db")
    shared_grant(db, "gr_race", 1)
    a = AgentLoopService(gate=PepCapabilityGate(db))
    b = AgentLoopService(gate=PepCapabilityGate(db))
    a.start_loop(LoopConfig(loop_id="loop-race-a"), capability_token="gr_race")
    b.start_loop(LoopConfig(loop_id="loop-race-b"), capability_token="gr_race")
    assert a.advance_turn("loop-race-a", "x", tool_name="pentest.nmap", tool_args={"target": "10.0.0.1"},
                          capability_token="gr_race").outcome == "ok"
    b._gate.irreversible_used = lambda gid: 0          # stale read, as if both checked at the same instant
    late = b.advance_turn("loop-race-b", "x", tool_name="pentest.nmap", tool_args={"target": "10.0.0.2"},
                          capability_token="gr_race")
    assert late.outcome == "refused" and "used 1 of 1" in late.error_message
    assert late.policy["irreversible_used"] == 1
    assert ok_irreversible(db, "gr_race") == 1
    assert len(b.get_snapshot("loop-race-b").steps) == 1     # the refused step is still recorded once
    with closing(audit_client.open_db(db)) as conn:
        assert audit_client.verify(conn)["ok"] is True


def _racer(db, n, q):
    try:
        svc = AgentLoopService(gate=PepCapabilityGate(db, busy_timeout_ms=20000))
        svc.start_loop(LoopConfig(loop_id=f"loop-race-p{n}"), capability_token="gr_race_mp")
        outs = [svc.advance_turn(f"loop-race-p{n}", "x", tool_name="pentest.nmap",
                                 tool_args={"target": f"10.0.0.{n * 10 + i}"}, capability_token="gr_race_mp").outcome
                for i in range(3)]
        q.put(outs)
    except BaseException as exc:
        q.put(f"{type(exc).__name__}: {exc}")


def test_parallel_processes_never_overspend_a_shared_budget(tmp_path):
    db = str(tmp_path / "audit.db")
    budget = 3
    shared_grant(db, "gr_race_mp", budget)
    q = mp.Queue()
    procs = [mp.Process(target=_racer, args=(db, n, q)) for n in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=120)
    assert not any(p.is_alive() for p in procs)
    results = [q.get(timeout=10) for _ in procs]
    assert all(isinstance(r, list) for r in results), results
    assert sum(r.count("ok") for r in results) == budget          # exactly the budget, never more
    assert ok_irreversible(db, "gr_race_mp") == budget
