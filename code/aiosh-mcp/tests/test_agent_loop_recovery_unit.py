"""Unit tests for agent-loop recovery & validation (T-03357).

Each problem kind on a hand-built ring, boundaries (grace, listing cap), and the primary
failure modes (concurrent double recovery, replayed grant, corrupt DB, legacy rows).
"""

import json
import threading
from contextlib import closing

import pytest

from agent_loop_grants import mint_grant
from aiosh_mcp import agent_loop_recovery as rec
from aiosh_mcp import audit_client
from aiosh_mcp.agent_loop_gate import AGENT_LOOP_ACTOR_ID


def write(db, event, run_id, loop_id="loop-u-01", outcome="ok", grant="g1", actor=AGENT_LOOP_ACTOR_ID, **args):
    payload = {"loop_id": loop_id, **({"run_id": run_id} if run_id else {}), **{k: str(v) for k, v in args.items()}}
    with closing(audit_client.open_db(db)) as conn:
        audit_client.write_audit_row(conn, {
            "ts": audit_client.utcnow_iso(), "actor": "agent", "actor_id": actor, "tool": f"aios.agent_loop.{event}",
            "command": "c", "args": payload, "target": None, "outcome": outcome, "outcome_detail": None,
            "constitution_rev": None, "grant_token": grant, "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True}})


def run(db, run_id, steps=2, terminal="complete", loop_id="loop-u-01", actor=AGENT_LOOP_ACTOR_ID):
    write(db, "start", run_id, loop_id, actor=actor)
    for i in range(steps):
        write(db, "step", run_id, loop_id, actor=actor, step_index=i, irreversible=False)
    if terminal:
        write(db, terminal, run_id, loop_id, actor=actor)


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "audit.db")


@pytest.fixture
def aged(monkeypatch):
    """Moves recovery's clock past the maximum run timeout (T-03359: a run is only orphaned once it
    can no longer legitimately step), while staying inside a 3600 s grace."""
    import datetime as _dt
    from aiosh_mcp import agent_loop_recovery as _rec
    later = _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=_rec.MAX_TOTAL_TIMEOUT_S + 100)
    monkeypatch.setattr(_rec, "_now", lambda: later)
    return later


def kinds(r):
    return sorted({p["kind"] for p in r["problems"]})


@pytest.mark.parametrize("build,kind", [
    (lambda d: (run(d, "r1"), write(d, "step", "r1", step_index=2)), "rows_after_terminal"),
    (lambda d: (write(d, "start", "r1"), run(d, "r1", steps=0)), "duplicate_start"),
    (lambda d: (write(d, "start", "r1"), write(d, "step", "r1", step_index=0), write(d, "step", "r1", step_index=2),
                write(d, "complete", "r1")), "step_index_gap"),
    (lambda d: (run(d, "r1"), run(d, "r2")), "run_id_mixed"),
    (lambda d: (write(d, "step", "r1", step_index=0), write(d, "complete", "r1")), "missing_start"),
])
def test_each_problem_kind(db, build, kind):
    build(db)
    r = rec.validate_ring(db, grace_s=0)
    assert kind in kinds(r) and r["ok"] is False


def test_budget_exceeded(db):
    mint_grant(db, "gr_budget")
    with closing(audit_client.open_db(db)) as conn:
        conn.execute("UPDATE pep_grants SET scope_json=? WHERE grant_id='gr_budget'",
                     (json.dumps({"tools": ["x"], "max_irreversible": 1}),))
        conn.commit()
    write(db, "start", "r1", grant="gr_budget")
    for i in range(2):
        write(db, "step", "r1", step_index=i, irreversible=True, grant="gr_budget")
    write(db, "complete", "r1", grant="gr_budget")
    r = rec.validate_ring(db, grace_s=0)
    assert kinds(r) == ["budget_exceeded"] and "gr_budget" not in json.dumps(r)    # grant hashed


def test_grace_boundary_and_untrusted_rows(db, aged):
    run(db, "r1", terminal=None)
    run(db, "r9", terminal=None, loop_id="loop-u-09", actor="agent:forger")     # untrusted: ignored entirely
    assert rec.validate_ring(db, grace_s=10_000)["orphaned"] == []
    r = rec.validate_ring(db, grace_s=0)
    assert [o["run_id"] for o in r["orphaned"]] == ["r1"] and r["runs"] == 1


def test_legacy_rows_without_run_id_are_skipped(db):
    write(db, "start", None)
    write(db, "step", None, step_index=0)
    assert rec.validate_ring(db, grace_s=0)["runs"] == 0


def test_listing_is_capped(db, aged):
    for i in range(5):
        run(db, f"r{i}", steps=0, terminal=None, loop_id=f"loop-u-{i:02d}")
    r = rec.validate_ring(db, grace_s=0, max_listed=3)
    assert len(r["orphaned"]) == 3 and r["truncated"] is True


def test_concurrent_recoveries_close_each_run_once(db, aged):
    for i in range(4):
        run(db, f"r{i}", steps=1, terminal=None, loop_id=f"loop-u-{i:02d}")
    mint_grant(db, "gr_rec_1", tools=["aios.agent_loop.recover"])
    mint_grant(db, "gr_rec_2", tools=["aios.agent_loop.recover"])
    results, errors = [], []

    def worker(tok):
        try:
            results.append(rec.recover_orphans(db, tok, grace_s=0))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    ts = [threading.Thread(target=worker, args=(t,)) for t in ("gr_rec_1", "gr_rec_2")]
    for t in ts:
        t.start()
    for t in ts:
        t.join(60)
    assert not errors
    assert sum(len(r["recovered"]) for r in results) == 4                  # each run closed exactly once
    with closing(audit_client.open_db(db)) as conn:
        n = conn.execute("SELECT count(*) FROM audit_ring WHERE tool='aios.agent_loop.recovered'").fetchone()[0]
    assert n == 4 and rec.validate_ring(db, grace_s=0)["ok"] is True


def test_replayed_recovery_grant_refused(db, aged):
    run(db, "r1", terminal=None)
    mint_grant(db, "gr_once", tools=["aios.agent_loop.recover"])
    rec.recover_orphans(db, "gr_once", grace_s=0)
    run(db, "r2", terminal=None, loop_id="loop-u-02")
    with pytest.raises(rec.RecoveryError) as exc:
        rec.recover_orphans(db, "gr_once", grace_s=0)
    assert exc.value.code == "LOOPSERV_ERR_UNAUTHORIZED"


def test_corrupt_db(tmp_path):
    bad = tmp_path / "corrupt.db"
    bad.write_bytes(b"not sqlite" * 300)
    with pytest.raises(rec.RecoveryError) as exc:
        rec.validate_ring(str(bad))
    assert exc.value.code == rec.LOOPREC_ERR_READ
