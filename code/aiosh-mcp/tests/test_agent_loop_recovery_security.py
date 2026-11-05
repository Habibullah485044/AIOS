"""Regression tests for the recovery & validation security review (T-03359).

Each test fails on the pre-T-03359 code (verified by stashing the fix; see
docs/tasks/evidence/T-03359-security.md).
"""

import datetime as dt
import sqlite3
from contextlib import closing

import pytest

from agent_loop_grants import mint_grant
from aiosh_mcp import agent_loop_recovery as rec
from aiosh_mcp import audit_client
from aiosh_mcp.agent_loop_data_model import LoopConfig
from aiosh_mcp.agent_loop_gate import PepCapabilityGate, read_loop_history
from aiosh_mcp.agent_loop_service import AgentLoopService, AgentLoopServiceError


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "audit.db")
    mint_grant(path, "gr_sec_run", tools=["aios.agent_loop.start", "aios.fs.*"])
    mint_grant(path, "gr_sec_recover", tools=["aios.agent_loop.recover"])
    return path


def shift_clock(monkeypatch, seconds):
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)
    monkeypatch.setattr(rec, "_now", lambda: later, raising=False)


def started(db, lid, steps=1, **cfg):
    grant = f"gr_{lid}"                                              # start grants are single-use
    mint_grant(db, grant, tools=["aios.agent_loop.start", "aios.fs.*"])
    s = AgentLoopService(gate=PepCapabilityGate(db))
    s.start_loop(LoopConfig(loop_id=lid, **cfg), capability_token=grant)
    for _ in range(steps):
        s.advance_turn(lid, "x", tool_name="aios.fs.read", tool_args={"path": "a"}, capability_token=grant)
    return s


def events(db, lid):
    return [e["tool"].rsplit(".", 1)[1] for e in read_loop_history(db, lid, 100)]


# --- #1: a run another process is still stepping must not be closed ------------------------------------------

def test_run_within_its_total_timeout_is_not_orphaned(db, monkeypatch):
    started(db, "loop-sec-slow", total_timeout_ms=300000)          # alive elsewhere, just quiet
    assert rec.validate_ring(db, grace_s=0)["orphaned"] == []
    shift_clock(monkeypatch, 200)                                    # idle past grace, still inside its 300 s
    assert rec.validate_ring(db, grace_s=0)["orphaned"] == []
    shift_clock(monkeypatch, 302)                                    # can no longer legitimately step
    assert [o["loop_id"] for o in rec.validate_ring(db, grace_s=0)["orphaned"]] == ["loop-sec-slow"]


def test_row_written_after_validation_blocks_recovery(db, monkeypatch):
    s = started(db, "loop-sec-race", total_timeout_ms=5000)
    shift_clock(monkeypatch, 3600)
    real = rec.validate_ring

    def validate_then_other_process_steps(*a, **kw):
        report = real(*a, **kw)
        s.advance_turn("loop-sec-race", "x", tool_name="aios.fs.read", tool_args={"path": "a"},
                       capability_token="gr_loop-sec-race")         # the run proves it is alive
        return report

    monkeypatch.setattr(rec, "validate_ring", validate_then_other_process_steps)
    out = rec.recover_orphans(db, "gr_sec_recover", grace_s=0)
    assert out["recovered"] == []
    assert "recovered" not in events(db, "loop-sec-race")


def test_recovered_run_stops_writing(db, monkeypatch):
    s = started(db, "loop-sec-late", total_timeout_ms=300000)       # stalled, not dead
    shift_clock(monkeypatch, 3600)
    assert [o["loop_id"] for o in rec.recover_orphans(db, "gr_sec_recover", grace_s=0)["recovered"]] == \
        ["loop-sec-late"]
    with pytest.raises(AgentLoopServiceError) as exc:
        s.advance_turn("loop-sec-late", "x", tool_name="aios.fs.read", tool_args={"path": "a"},
                       capability_token="gr_loop-sec-late")
    assert exc.value.code == "LOOPSERV_ERR_TERMINATED"
    assert events(db, "loop-sec-late") == ["start", "step", "recovered"]   # nothing after the terminal row
    assert rec.validate_ring(db, grace_s=0)["problems"] == []


# --- #2: write_audit_row must not commit the caller's open transaction -------------------------------------------

def test_write_audit_row_keeps_the_callers_lock(tmp_path, monkeypatch):
    path = str(tmp_path / "audit.db")
    with closing(audit_client.open_db(path)) as conn:
        audit_client.ensure_pep_schema(conn)
        conn.execute("CREATE TABLE IF NOT EXISTS probe (v INTEGER)")
        conn.commit()
    seen = []
    real_insert = audit_client._insert_audit_row

    def spy(conn, proto, **kw):
        with closing(sqlite3.connect(path, timeout=0.1)) as other:
            seen.append(other.execute("SELECT count(*) FROM probe").fetchone()[0])
        return real_insert(conn, proto, **kw)

    monkeypatch.setattr(audit_client, "_insert_audit_row", spy)
    with closing(audit_client.open_db(path)) as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO probe VALUES (1)")                # the caller's checked work
        audit_client.write_audit_row(conn, {
            "ts": audit_client.utcnow_iso(), "actor": "agent", "actor_id": "a", "tool": "t", "command": "c",
            "args": {}, "target": None, "outcome": "ok", "outcome_detail": None, "constitution_rev": None,
            "grant_token": None, "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True}})
    assert seen == [0]          # not committed (and the lock not released) before the audit insert


# --- #3: recovery needs an explicit grant, not a glob ------------------------------------------------------------

@pytest.mark.parametrize("tools", [["aios.agent_loop.*"], ["*"], ["aios.*"]])
def test_glob_grant_cannot_recover(db, monkeypatch, tools):
    started(db, "loop-sec-glob", total_timeout_ms=5000)
    shift_clock(monkeypatch, 3600)
    mint_grant(db, "gr_sec_glob", tools=tools)
    with pytest.raises(rec.RecoveryError) as exc:
        rec.recover_orphans(db, "gr_sec_glob", grace_s=0)
    assert exc.value.code == "LOOPSERV_ERR_UNAUTHORIZED"
    assert "recovered" not in events(db, "loop-sec-glob")


# --- #4: bounded cost of the tokenless validate call --------------------------------------------------------------

def test_chain_check_is_opt_in_and_scan_is_windowed(db):
    for lid in ("loop-sec-w1", "loop-sec-w2"):
        s = started(db, lid, steps=0)
        s.complete_loop(lid, capability_token=f"gr_{lid}")
    assert rec.validate_ring(db)["chain_ok"] is None
    assert rec.validate_ring(db, verify_chain=True)["chain_ok"] is True
    assert rec.validate_ring(db, window=2)["runs"] == 1             # only the newest rows are scanned


# --- #5: a secret-shaped loop_id would be stored masked and alias other loops --------------------------------------

@pytest.mark.parametrize("lid", ["sk-" + "a" * 24, "ghp_" + "b" * 24, "AKIA" + "C" * 16])
def test_secret_shaped_loop_id_rejected(db, lid):
    with pytest.raises(ValueError, match="LOOPDATA_ERR_BOUNDS_EXCEEDED") as exc:
        LoopConfig(loop_id=lid).validate_bounds()
    assert lid not in str(exc.value)                                 # the error does not echo the credential
    mint_grant(db, "gr_sec_secret", tools=["aios.agent_loop.start"])
    with pytest.raises((ValueError, AgentLoopServiceError)) as exc:
        AgentLoopService(gate=PepCapabilityGate(db)).start_loop(LoopConfig(loop_id=lid), capability_token="gr_sec_secret")
    assert lid not in str(exc.value)
    assert read_loop_history(db, lid, 10) == []


def test_live_runs_reported_honestly(db, monkeypatch):
    s = started(db, "loop-sec-live", total_timeout_ms=5000)
    shift_clock(monkeypatch, 3600)
    r = rec.validate_ring(db, grace_s=0, live_runs=[s.run_id("loop-sec-live")])
    assert (r["open"], r["skipped_live"], r["orphaned"]) == (1, 1, [])
