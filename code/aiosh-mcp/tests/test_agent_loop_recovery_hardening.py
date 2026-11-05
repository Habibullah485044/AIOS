"""Hardening tests for agent-loop recovery & validation (T-03360).

Failure modes produce explicit, auditable errors; no lock or connection is left held on the error path.
"""

import datetime as dt
import json
import sqlite3
import time
from contextlib import closing

import pytest

from agent_loop_grants import mint_grant
from aiosh_mcp import agent_loop_recovery as rec
from aiosh_mcp import audit_client
from aiosh_mcp.agent_loop_cli import dispatch_cli
from aiosh_mcp.agent_loop_data_model import LoopConfig
from aiosh_mcp.agent_loop_gate import PepCapabilityGate, read_loop_history
from aiosh_mcp.agent_loop_service import AgentLoopService


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = str(tmp_path / "audit.db")
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=3600)
    monkeypatch.setattr(rec, "_now", lambda: later)
    return path


def crash(db, lid):
    grant = f"gr_{lid}"
    mint_grant(db, grant, tools=["aios.agent_loop.start", "aios.fs.*"])
    s = AgentLoopService(gate=PepCapabilityGate(db))
    s.start_loop(LoopConfig(loop_id=lid, total_timeout_ms=5000), capability_token=grant)
    s.advance_turn(lid, "x", tool_name="aios.fs.read", tool_args={"path": "a"}, capability_token=grant)
    return grant


def lock_is_free(db):
    with closing(sqlite3.connect(db, timeout=0)) as other:
        other.execute("BEGIN IMMEDIATE")
        other.rollback()
    return True


def test_malformed_grant_budget_is_a_problem_not_a_crash(db):
    grant = crash(db, "loop-hard-bud1")
    with closing(audit_client.open_db(db)) as conn:
        conn.execute("UPDATE pep_grants SET scope_json=? WHERE grant_id=?",
                     (json.dumps({"tools": ["x"], "max_irreversible": "lots"}), grant))
        conn.commit()
    r = rec.validate_ring(db, grace_s=0)
    assert "budget_invalid" in {p["kind"] for p in r["problems"]} and r["ok"] is False
    assert grant not in json.dumps(r)                                   # grant ids stay hashed


def test_unparseable_grant_row_is_a_read_error(db):
    grant = crash(db, "loop-hard-bud2")
    with closing(audit_client.open_db(db)) as conn:
        conn.execute("UPDATE pep_grants SET scope_json='{not json' WHERE grant_id=?", (grant,))
        conn.commit()
    with pytest.raises(rec.RecoveryError) as exc:
        rec.validate_ring(db, grace_s=0)
    assert exc.value.code == rec.LOOPREC_ERR_READ


def test_validation_deadline(db, monkeypatch):
    crash(db, "loop-hard-dl01")
    ticks = iter(range(0, 10**6, 100))                                 # every clock read is 100 s later
    monkeypatch.setattr(rec.time, "monotonic", lambda: next(ticks))
    with pytest.raises(rec.RecoveryError) as exc:
        rec.validate_ring(db, grace_s=0, deadline_s=10)
    assert exc.value.code == rec.LOOPREC_ERR_READ and "budget" in str(exc.value)
    assert lock_is_free(db)


def test_write_failure_is_explicit_partial_and_releases_the_lock(db, monkeypatch):
    for lid in ("loop-hard-wf01", "loop-hard-wf02"):
        crash(db, lid)
    mint_grant(db, "gr_hard_rec", tools=["aios.agent_loop.recover"])
    real, calls = audit_client.write_audit_row, []

    def fail_second(conn, proto, **kw):
        if proto["tool"] == "aios.agent_loop.recovered":
            calls.append(1)
            if len(calls) == 2:
                raise sqlite3.OperationalError("database or disk is full")
        return real(conn, proto, **kw)

    monkeypatch.setattr(audit_client, "write_audit_row", fail_second)
    with pytest.raises(rec.RecoveryError) as exc:
        rec.recover_orphans(db, "gr_hard_rec", grace_s=0)
    assert exc.value.code == rec.LOOPREC_ERR_WRITE and "after 1 of 2" in str(exc.value)
    assert len(exc.value.recovered) == 1                               # honest partial result
    assert lock_is_free(db)                                            # no transaction left open
    monkeypatch.setattr(audit_client, "write_audit_row", real)
    left = rec.validate_ring(db, grace_s=0)["orphaned"]
    assert [o["run_id"] for o in left] != [exc.value.recovered[0]["run_id"]] and len(left) == 1
    mint_grant(db, "gr_hard_rec2", tools=["aios.agent_loop.recover"])
    assert len(rec.recover_orphans(db, "gr_hard_rec2", grace_s=0)["recovered"]) == 1   # re-run finishes the job
    assert rec.validate_ring(db, grace_s=0)["ok"] is True


def test_locked_db_is_bounded_and_explicit(db, monkeypatch):
    from aiosh_mcp import agent_loop_config as cfg
    crash(db, "loop-hard-lk01")
    mint_grant(db, "gr_hard_lock", tools=["aios.agent_loop.recover"])
    real_cfg = cfg.process_config()
    patched = {**real_cfg, "config": {**real_cfg["config"], "db_busy_timeout_ms": 200}}
    monkeypatch.setattr(cfg, "process_config", lambda: patched)
    holder = sqlite3.connect(db)
    holder.execute("BEGIN IMMEDIATE")
    try:
        t = time.monotonic()
        with pytest.raises(rec.RecoveryError) as exc:
            rec.recover_orphans(db, "gr_hard_lock", grace_s=0)
        assert time.monotonic() - t < 3.0                              # bounded by the configured busy timeout
        assert exc.value.code == rec.LOOPREC_ERR_WRITE
    finally:
        holder.rollback()
        holder.close()
    # the grant was not consumed by the failed attempt, so recovery can simply be retried
    assert len(rec.recover_orphans(db, "gr_hard_lock", grace_s=0)["recovered"]) == 1


def test_cli_reports_write_failure_in_the_envelope(db, monkeypatch):
    crash(db, "loop-hard-cli1")
    mint_grant(db, "gr_hard_cli", tools=["aios.agent_loop.recover"])

    def boom(conn, proto, **kw):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(audit_client, "write_audit_row", boom)
    monkeypatch.setenv("AIOS_HARD_GRANT", "gr_hard_cli")
    out = dispatch_cli(["recover", "--token-env", "AIOS_HARD_GRANT", "--grace", "0", "--json"], db_path=db)
    assert out.exit_code != 0 and out.error_code == rec.LOOPREC_ERR_WRITE
    assert "recovered" not in [e["tool"].rsplit(".", 1)[1] for e in read_loop_history(db, "loop-hard-cli1", 50)]


def test_malformed_timeout_cannot_make_a_run_recoverable_early(tmp_path):
    path = str(tmp_path / "audit.db")
    with closing(audit_client.open_db(path)) as conn:
        for tool, args in (("start", {"run_id": "r1", "total_timeout_ms": "-99999999"}),
                           ("step", {"run_id": "r1", "step_index": "0"})):
            audit_client.write_audit_row(conn, {
                "ts": audit_client.utcnow_iso(), "actor": "agent", "actor_id": rec.AGENT_LOOP_ACTOR_ID,
                "tool": f"aios.agent_loop.{tool}", "command": "c", "args": {"loop_id": "loop-hard-to01", **args},
                "target": None, "outcome": "ok", "outcome_detail": None, "constitution_rev": None,
                "grant_token": None, "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True}})
    assert rec.validate_ring(path, grace_s=0)["orphaned"] == []          # clamped to the 5 s minimum
