"""Implementation tests for agent-loop observability (T-03336; spec T-03334)."""

import json
import logging
import sqlite3

import pytest

from agent_loop_grants import AllowAllGate, mint_grant
from aiosh_mcp import agent_loop_observability as obs
from aiosh_mcp.agent_loop_data_model import LoopConfig
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_service import AgentLoopService

GRANT = "gr_obs_secret_bearer_0001"


@pytest.fixture
def run(tmp_path):
    db = str(tmp_path / "audit.db")
    mint_grant(db, GRANT, tools=["aios.agent_loop.start", "aios.fs.*", "fs.*"])
    svc = AgentLoopService(gate=PepCapabilityGate(db))
    svc.start_loop(LoopConfig(loop_id="loop-obs-01"), capability_token=GRANT)
    svc.advance_turn("loop-obs-01", "read", tool_name="aios.fs.read", tool_args={"path": "README.md"},
                     capability_token=GRANT)
    svc.advance_turn("loop-obs-01", "write", tool_name="fs.write", tool_args={"path": "/tmp/x"},
                     capability_token=GRANT)                                   # constitution refusal
    svc.advance_turn("loop-obs-01", "no", tool_name="aios.fs.read", policy_allowed=False,
                     capability_token=GRANT)                                   # caller refusal
    svc.complete_loop("loop-obs-01", capability_token=GRANT)
    return svc, db


def test_durations_are_measured_not_constants(run):
    svc, db = run
    steps = svc.get_snapshot("loop-obs-01").steps
    assert all(s.duration_ms not in (5.0, 15.0) and s.duration_ms >= 0 for s in steps)
    rows = [json.loads(r[0]) for r in sqlite3.connect(db).execute(
        "SELECT args_json FROM audit_ring WHERE tool='aios.agent_loop.step'")]
    assert [float(r["duration_ms"]) for r in rows] == [s.duration_ms for s in steps]


def test_ring_metrics(run):
    _, db = run
    m = obs.ring_metrics(db)
    assert m["events"]["start"] == 1 and m["events"]["step"] == 3 and m["events"]["complete"] == 1
    assert m["steps"]["ok"] + m["steps"]["refused"] == m["events"]["step"]          # LOOPOBS-INV2
    assert (m["refusals"]["constitution"], m["refusals"]["caller"]) == (1, 1)
    assert m["steps"]["duration_ms"]["count"] == 3 and m["steps"]["duration_ms"]["p95"] is not None
    assert GRANT not in json.dumps(m)                                               # LOOPOBS-INV1


def test_ring_metrics_window_and_missing_db(tmp_path, run):
    _, db = run
    assert obs.ring_metrics(db, window=2)["window"]["rows"] == 2
    assert obs.ring_metrics(str(tmp_path / "none.db"))["window"]["rows"] == 0
    for bad in (0, obs.MAX_WINDOW + 1, True, "10"):
        with pytest.raises(ValueError):
            obs.ring_metrics(db, window=bad)


def test_irreversible_by_grant_is_hashed(tmp_path):
    db = str(tmp_path / "audit.db")
    mint_grant(db, GRANT, tools=["aios.agent_loop.start", "pentest.*"])
    svc = AgentLoopService(gate=PepCapabilityGate(db))
    svc.start_loop(LoopConfig(loop_id="loop-obs-02"), capability_token=GRANT)
    svc.advance_turn("loop-obs-02", "scan", tool_name="pentest.nmap", tool_args={"target": "10.0.0.5"},
                     capability_token=GRANT)
    m = obs.ring_metrics(db)
    assert m["steps"]["irreversible_ok"] == 1
    assert len(m["irreversible_by_grant"]) == 1 and len(m["irreversible_by_grant"][0]["grant_hash"]) == 12
    assert GRANT not in json.dumps(m)


def test_live_stats(run):
    svc, _ = run
    st = svc.stats()
    assert (st["active_loops"], st["terminated_loops"]) == (0, 1)
    assert st["counters"]["steps_ok"] == 1 and st["counters"]["steps_refused"] == 2


@pytest.mark.parametrize("detail,reason", [
    ("LOOPSERV_ERR_POLICY_REFUSED: ... LOOPPOL_ERR_CONSTITUTION: c2", "constitution"),
    ("... LOOPPOL_ERR_IRREVERSIBLE_BUDGET: used 1 of 1", "irreversible_budget"),
    ("... tool 'x' not in grant scope.tools", "scope"),
    ("... target '8.8.8.8' blocked by grant scope.networks", "scope"),
    ("... caller policy verdict", "caller"),
    ("... LOOPSERV_ERR_GATE_UNAVAILABLE: db locked", "gate_unavailable"),
    ("... LOOPPOL_ERR_TARGET: non-string", "target"),
    (None, "other"), ("weird", "other"),
])
def test_classify_refusal(detail, reason):
    assert obs.classify_refusal(detail) == reason


def test_health_states():
    clean = {"refusals": {}, "degraded_config_rows": 0}
    assert obs.health(clean) == "ok"
    assert obs.health(clean, config_degraded=True) == "degraded"
    assert obs.health({**clean, "degraded_config_rows": 1}) == "degraded"
    assert obs.health(clean, {"counters": {"gate_unavailable": 1}}) == "degraded"
    assert obs.health(clean, {"counters": {"audit_failures": 1}}) == "failing"
    assert obs.health({"error": "unreadable"}) == "failing"


def test_logs_are_structured_and_leak_nothing(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="aiosh_mcp.agent_loop")
    db = str(tmp_path / "audit.db")
    mint_grant(db, GRANT, tools=["aios.agent_loop.start", "aios.fs.*"])
    svc = AgentLoopService(gate=PepCapabilityGate(db))
    svc.start_loop(LoopConfig(loop_id="loop-obs-03"), capability_token=GRANT)
    svc.advance_turn("loop-obs-03", "read", tool_name="aios.fs.read",
                     tool_args={"path": "x", "auth": "Bearer sk-abcdefghijklmnopqrstuvwxyz0123"}, capability_token=GRANT)
    svc.abort_loop("loop-obs-03", "done", capability_token=GRANT)
    events = [r.agent_loop["event"] for r in caplog.records if hasattr(r, "agent_loop")]
    assert events == ["start", "step", "abort"]
    text = "\n".join(r.getMessage() + json.dumps(r.agent_loop) for r in caplog.records)
    assert GRANT not in text and "sk-abcdef" not in text and "auth" not in text


def test_audit_failure_is_counted_and_logged(caplog):
    caplog.set_level(logging.WARNING, logger="aiosh_mcp.agent_loop")

    class Broken(AllowAllGate):
        def audit(self, event, *a, **k):
            if event == "step":
                raise OSError("ring unwritable")
            return super().audit(event, *a, **k)

    svc = AgentLoopService(gate=Broken())
    svc.start_loop(LoopConfig(loop_id="loop-obs-04"), capability_token="t")
    with pytest.raises(Exception):
        svc.advance_turn("loop-obs-04", "x", capability_token="t")
    assert svc.stats()["counters"]["audit_failures"] == 1
    assert any(getattr(r, "agent_loop", {}).get("event") == "audit_failure" for r in caplog.records)
    assert obs.health({}, svc.stats()) == "failing"
