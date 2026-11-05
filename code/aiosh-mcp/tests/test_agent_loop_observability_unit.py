"""Unit tests for agent-loop observability (T-03337).

Valid input, invalid input, boundaries and failure modes of ring_metrics, the percentile
helper, health and log_event, on hand-built audit rings.
"""

import json
import logging
from contextlib import closing

import pytest

from aiosh_mcp import agent_loop_observability as obs
from aiosh_mcp import audit_client


def ring(tmp_path, rows):
    """rows: (tool, outcome, outcome_detail, args, grant)."""
    db = str(tmp_path / "audit.db")
    with closing(audit_client.open_db(db)) as conn:
        for tool, outcome, detail, args, grant in rows:
            audit_client.write_audit_row(conn, {
                "ts": audit_client.utcnow_iso(), "actor": "agent", "actor_id": "t", "tool": tool,
                "command": "c", "args": args, "target": None, "outcome": outcome, "outcome_detail": detail,
                "constitution_rev": None, "grant_token": grant,
                "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True}})
    return db


def step(outcome="ok", detail=None, duration="1.0", irreversible="False", grant="g1"):
    args = {"loop_id": "l", "irreversible": irreversible}
    if duration is not None:
        args["duration_ms"] = duration
    return ("aios.agent_loop.step", outcome, detail, args, grant)


def test_non_agent_loop_rows_are_ignored(tmp_path):
    # 'aios.agentXloop.step' would match LIKE 'aios.agent_loop.%' ('_' is a LIKE wildcard).
    db = ring(tmp_path, [("pentest.nmap", "ok", None, {}, None), ("aios_agent_loop.step", "ok", None, {}, None),
                         ("aios.agentXloop.step", "ok", None, {"loop_id": "l"}, None),
                         ("aios.agent_loopX", "ok", None, {}, None), step()])
    m = obs.ring_metrics(db)
    assert m["window"]["rows"] == 1 and m["events"]["step"] == 1


def test_window_boundaries(tmp_path):
    db = ring(tmp_path, [step() for _ in range(5)])
    assert obs.ring_metrics(db, window=1)["window"]["rows"] == 1
    assert obs.ring_metrics(db, window=obs.MAX_WINDOW)["window"]["rows"] == 5
    w = obs.ring_metrics(db, window=3)["window"]
    assert w["last_id"] - w["first_id"] == 2          # the newest 3, oldest first


def test_rows_without_duration_and_malformed_args(tmp_path):
    db = ring(tmp_path, [step(duration=None), step(duration="abc"), step(duration="4.5")])
    d = obs.ring_metrics(db)["steps"]["duration_ms"]
    assert d == {"count": 1, "p50": 4.5, "p95": 4.5, "max": 4.5}


@pytest.mark.parametrize("values,q,expected", [
    ([], 0.5, None), ([7.0], 0.95, 7.0), ([1.0, 2.0, 3.0, 4.0], 0.5, 3.0), ([3.0, 1.0, 2.0], 0.0, 1.0),
    (list(map(float, range(1, 101))), 0.95, 95.0),
])
def test_percentile_helper(values, q, expected):
    assert obs._pct(values, q) == expected


def test_degraded_config_and_irreversible_grouping(tmp_path):
    db = ring(tmp_path, [("aios.agent_loop.config", "degraded", "x", {}, None),
                         step(irreversible="True", grant="ga"), step(irreversible="True", grant="ga"),
                         step(irreversible="True", grant="gb"), step(outcome="refused", irreversible="True", grant="gb")])
    m = obs.ring_metrics(db)
    assert m["degraded_config_rows"] == 1 and m["steps"]["irreversible_ok"] == 3
    assert sorted(x["ok"] for x in m["irreversible_by_grant"]) == [1, 2]
    assert "ga" not in json.dumps(m["irreversible_by_grant"])
    assert obs.health(m) == "degraded"


def test_corrupt_db_raises_read_error(tmp_path):
    bad = tmp_path / "corrupt.db"
    bad.write_bytes(b"not a database" * 100)
    with pytest.raises(obs.ObservabilityReadError) as exc:
        obs.ring_metrics(str(bad))
    assert obs.LOOPOBS_ERR_READ in str(exc.value)


def test_db_without_audit_table(tmp_path):
    import sqlite3
    p = tmp_path / "other.db"
    sqlite3.connect(p).execute("CREATE TABLE t (x)").connection.close()
    assert obs.ring_metrics(str(p))["window"]["rows"] == 0


def test_log_event_respects_level_and_masks(caplog):
    caplog.set_level(logging.WARNING, logger="aiosh_mcp.agent_loop")
    obs.log_event("step", "loop-x", "r1", "ok")                         # INFO: filtered out
    assert caplog.records == []
    obs.log_event("audit_failure", "loop-x", "r1", "error", reason="Bearer sk-abcdefghijklmnopqrstuvwxyz0123 " + "x" * 500,
                  level=logging.WARNING)
    rec = caplog.records[0]
    assert "sk-abcdef" not in rec.getMessage() and len(rec.agent_loop["reason"]) <= 200
    assert rec.agent_loop["event"] == "audit_failure"


def test_history_ignores_lookalike_tools(tmp_path):
    """read_loop_history used LIKE too: a lookalike tool row with the same loop_id must not appear."""
    from aiosh_mcp.agent_loop_gate import read_loop_history
    db = ring(tmp_path, [("aios.agentXloop.step", "ok", None, {"loop_id": "loop-lookalike"}, None),
                         ("aios.agent_loop.step", "ok", None, {"loop_id": "loop-lookalike"}, None)])
    assert [e["tool"] for e in read_loop_history(db, "loop-lookalike", 10)] == ["aios.agent_loop.step"]
