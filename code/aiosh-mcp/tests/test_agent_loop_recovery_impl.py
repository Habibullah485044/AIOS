"""Implementation tests for agent-loop recovery & validation (T-03356; spec T-03354)."""

import sqlite3

import pytest

from agent_loop_grants import mint_grant
from aiosh_mcp import agent_loop_recovery as rec
from aiosh_mcp.agent_loop_data_model import LoopConfig
from aiosh_mcp.agent_loop_gate import PepCapabilityGate, read_loop_history
from aiosh_mcp.agent_loop_service import AgentLoopService


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "audit.db")
    for g in ("gr_rec_a", "gr_rec_b", "gr_rec_c"):
        mint_grant(path, g, tools=["aios.agent_loop.start", "aios.fs.*"])
    mint_grant(path, "gr_recover", tools=["aios.agent_loop.recover"])
    return path


def crash_run(db, gid, lid, steps=2):
    s = AgentLoopService(gate=PepCapabilityGate(db))
    s.start_loop(LoopConfig(loop_id=lid), capability_token=gid)
    for _ in range(steps):
        s.advance_turn(lid, "x", tool_name="aios.fs.read", tool_args={"path": "a"}, capability_token=gid)
    return s.run_id(lid)            # the service object is then dropped: a "crash"


def test_clean_ring_validates(db):
    s = AgentLoopService(gate=PepCapabilityGate(db))
    s.start_loop(LoopConfig(loop_id="loop-rec-clean"), capability_token="gr_rec_a")
    s.advance_turn("loop-rec-clean", "x", capability_token="gr_rec_a")
    s.complete_loop("loop-rec-clean", capability_token="gr_rec_a")
    r = rec.validate_ring(db)
    assert (r["runs"], r["open"], r["orphaned"], r["problems"], r["chain_ok"], r["ok"]) == (1, 0, [], [], True, True)


def test_orphan_detected_after_grace_and_recovered_once(db):
    run_id = crash_run(db, "gr_rec_a", "loop-rec-crash")
    assert rec.validate_ring(db, grace_s=3600)["orphaned"] == []          # within grace: just open
    r = rec.validate_ring(db, grace_s=0)
    assert [o["run_id"] for o in r["orphaned"]] == [run_id] and r["ok"] is False
    out = rec.recover_orphans(db, "gr_recover", grace_s=0)
    assert [o["run_id"] for o in out["recovered"]] == [run_id]
    events = [e["tool"].rsplit(".", 1)[1] for e in read_loop_history(db, "loop-rec-crash", 100)]
    assert events == ["start", "step", "step", "recovered"]
    after = rec.validate_ring(db, grace_s=0)
    assert after["orphaned"] == [] and after["ok"] is True                 # LOOPREC-INV1


def test_recovery_requires_a_scoped_grant(db):
    crash_run(db, "gr_rec_a", "loop-rec-auth")
    for token in ("", "forged", "gr_rec_b"):                               # gr_rec_b lacks aios.agent_loop.recover
        with pytest.raises(rec.RecoveryError) as exc:
            rec.recover_orphans(db, token, grace_s=0)
        assert exc.value.code == "LOOPSERV_ERR_UNAUTHORIZED"
    assert rec.validate_ring(db, grace_s=0)["orphaned"]                     # nothing was closed


def test_live_runs_are_never_recovered(db):
    run_id = crash_run(db, "gr_rec_a", "loop-rec-live")
    out = rec.recover_orphans(db, "gr_recover", grace_s=0, live_runs=[run_id])
    assert out["recovered"] == [] and out["skipped_live"] == 1


def test_breaker_writes_failed_terminal_row(db):
    s = AgentLoopService(gate=PepCapabilityGate(db))
    s.start_loop(LoopConfig(loop_id="loop-rec-brk", max_iterations=1), capability_token="gr_rec_c")
    s.advance_turn("loop-rec-brk", "x", capability_token="gr_rec_c")
    events = [e["tool"].rsplit(".", 1)[1] for e in read_loop_history(db, "loop-rec-brk", 100)]
    assert events == ["start", "step", "failed"]
    assert rec.validate_ring(db, grace_s=0)["ok"] is True                  # not mistaken for an orphan


def test_tampered_ring_reports_problems(db):
    run_id = crash_run(db, "gr_rec_a", "loop-rec-tamper", steps=3)
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM audit_ring WHERE tool='aios.agent_loop.step' AND json_extract(args_json,'$.step_index')='1'")
    conn.commit()
    r = rec.validate_ring(db, grace_s=0)
    kinds = {p["kind"] for p in r["problems"]}
    assert "step_index_gap" in kinds and r["chain_ok"] is False and r["ok"] is False


def test_validation_never_creates_the_db(tmp_path):
    missing = tmp_path / "none" / "audit.db"
    assert rec.validate_ring(str(missing))["runs"] == 0 and not missing.exists()
