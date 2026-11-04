"""Multi-process stress: several services drive loops on one audit ring (T-03320; spec T-03314 §3).

This is the deployment shape (MCP server + CLI runs + TS CLI on one ring). Asserts that every
process finishes, that the row counts per run match, that loop ids stay unique, and that the chain
remains linear and verifiable.
"""

import multiprocessing as mp
import sqlite3
from contextlib import closing

import pytest

from agent_loop_grants import mint_grant
from aiosh_mcp import audit_client

PROCS, LOOPS, TURNS = 4, 5, 6
JOIN_TIMEOUT_S = 180


def _worker(db: str, proc: int, result_q) -> None:
    try:
        from aiosh_mcp.agent_loop_data_model import LoopConfig
        from aiosh_mcp.agent_loop_gate import PepCapabilityGate
        from aiosh_mcp.agent_loop_service import AgentLoopService
        svc = AgentLoopService(gate=PepCapabilityGate(db, busy_timeout_ms=20000), capacity=LOOPS)
        for n in range(LOOPS):
            lid, gid = f"loop-stress-p{proc}-l{n}", f"gr_stress_p{proc}_l{n}"
            svc.start_loop(LoopConfig(loop_id=lid, max_iterations=TURNS + 1), capability_token=gid)
            for t in range(TURNS):
                svc.advance_turn(lid, f"turn {t}", tool_name="aios.fs.read" if t % 2 else "fs.write",
                                 tool_args={"path": f"/data/p{proc}/{t}"}, capability_token=gid)
            svc.complete_loop(lid, capability_token=gid)
        result_q.put((proc, "ok"))
    except BaseException as exc:  # report, never hang the parent
        result_q.put((proc, f"{type(exc).__name__}: {exc}"))


def test_parallel_processes_keep_one_verifiable_chain(tmp_path):
    db = str(tmp_path / "audit.db")
    for p in range(PROCS):
        for n in range(LOOPS):
            mint_grant(db, f"gr_stress_p{p}_l{n}", tools=["aios.agent_loop.start", "aios.fs.*"])
    q = mp.Queue()
    procs = [mp.Process(target=_worker, args=(db, p, q)) for p in range(PROCS)]
    for pr in procs:
        pr.start()
    for pr in procs:
        pr.join(timeout=JOIN_TIMEOUT_S)
    hung = [pr for pr in procs if pr.is_alive()]
    for pr in hung:
        pr.kill()
    assert not hung, f"{len(hung)} worker(s) hung past {JOIN_TIMEOUT_S}s"
    results = dict(q.get(timeout=10) for _ in procs)
    assert results == {p: "ok" for p in range(PROCS)}, results

    with closing(sqlite3.connect(db)) as conn:
        def count(tool):
            return conn.execute("SELECT count(*) FROM audit_ring WHERE tool = ?", (tool,)).fetchone()[0]
        assert count("aios.agent_loop.start") == PROCS * LOOPS
        assert count("aios.agent_loop.step") == PROCS * LOOPS * TURNS
        assert count("aios.agent_loop.complete") == PROCS * LOOPS
        assert count("pep.capability.redeem") == PROCS * LOOPS
        total, distinct = conn.execute("SELECT count(*), count(DISTINCT prev_hash) FROM audit_ring").fetchone()
        assert total == distinct, "chain forked under concurrency"
        ids = [r[0] for r in conn.execute(
            "SELECT json_extract(args_json, '$.loop_id') FROM audit_ring WHERE tool = 'aios.agent_loop.start'")]
        assert len(ids) == len(set(ids))
    with closing(audit_client.open_db(db)) as conn:
        assert audit_client.verify(conn)["ok"] is True
