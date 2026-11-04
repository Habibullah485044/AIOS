"""Regression: concurrent audit writers must not fork the hash chain (security audit finding #1)."""

import multiprocessing as mp
import os
from contextlib import closing

from aiosh_mcp import audit_client

PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _writer(db: str, n: int, tag: int) -> None:
    import sys
    sys.path.insert(0, PKG_ROOT)
    from aiosh_mcp import audit_client as ac
    with closing(ac.open_db(db)) as conn:
        conn.execute("PRAGMA busy_timeout = 10000")
        for i in range(n):
            ac.write_audit_row(conn, {
                "ts": ac.utcnow_iso(), "actor": "agent", "actor_id": f"test:{tag}",
                "tool": "test.concurrency", "command": "write", "args": {"tag": tag, "i": i},
                "target": None, "outcome": "ok", "outcome_detail": None, "constitution_rev": None,
                "grant_token": None, "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True},
            })


def test_four_processes_keep_one_linear_chain(tmp_path):
    db = str(tmp_path / "audit.db")
    with closing(audit_client.open_db(db)) as conn:
        audit_client.ensure_pep_schema(conn)
    procs = [mp.Process(target=_writer, args=(db, 50, t)) for t in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=120)
        assert p.exitcode == 0
    with closing(audit_client.open_db(db)) as conn:
        total, distinct_prev = conn.execute(
            "SELECT count(*), count(DISTINCT prev_hash) FROM audit_ring").fetchone()
        assert (total, distinct_prev) == (200, 200)
        assert audit_client.verify(conn)["ok"] is True
