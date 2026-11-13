"""Hardening tests for the tool registry security policy and the capability gate (T-03430).

Failure modes must produce explicit, auditable errors; nothing may leak a connection or hang; fail-closed refusals
must be honest in the audit row (ADR-0035 F-2)."""

import contextlib
import io
import json
import sqlite3
import threading
import time
from contextlib import closing

import pytest

from agent_loop_grants import mint_grant
from aiosh_mcp import capability_redeem as cr
from aiosh_mcp import tool_registry_cli as cli
from aiosh_mcp import tool_registry_config
from aiosh_mcp import tool_registry_policy as pol
from aiosh_mcp import tool_registry_service as trs

TOOL = "aios.mcp.recovery.repair"


@pytest.fixture
def db(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("AIOSH_HOME", str(home))
    monkeypatch.delenv(trs.ENV_MODE, raising=False)
    return str(home / "audit.db")


def strict(monkeypatch):
    monkeypatch.setenv(trs.ENV_MODE, "strict")
    tool_registry_config.reset_process_config()
    monkeypatch.setattr(trs, "_SERVICE", None)
    pol.reset_process_state()


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


# ---- explicit errors, never a traceback ------------------------------------------------------------------------

def test_cli_decide_reports_a_broken_policy_in_the_envelope(db, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("policy exploded")
    monkeypatch.setattr(pol, "preview", boom)
    code, out, err = run_cli("decide", "aios.fs.read", "--json")
    env = json.loads(out)
    assert code != 0 and env["ok"] is False and env["error_code"] == cli.TOOLCLI_ERR_UNAVAILABLE
    assert "Traceback" not in out + err and "policy exploded" not in out + err      # type only, no message text


def test_mcp_decide_reports_a_broken_policy_in_the_envelope(db, monkeypatch):
    from aiosh_mcp.server import mcp
    from aiosh_mcp.tool_registry_api import DECIDE_TOOL
    monkeypatch.setattr(pol, "preview", lambda *a, **k: (_ for _ in ()).throw(OSError("disk")))
    out = {t.name: t for t in mcp._tool_manager.list_tools()}[DECIDE_TOOL].fn(name="aios.fs.read")
    assert out["ok"] is False and out["error"]


@pytest.mark.parametrize("field,value", [("command", "c" * 100_000), ("target", "/" + "t" * 100_000)],
                         ids=["huge-command", "huge-target"])
def test_oversized_gate_inputs_are_refused_quickly(db, field, value):
    mint_grant(db, "g-big", tools=[TOOL])
    t0 = time.monotonic()
    reason = cr.redeem_capability("g-big", tool=TOOL, **{field: value})
    assert reason is not None and "malformed" in reason and time.monotonic() - t0 < 1.0
    assert cr.redeem_capability("g-big", tool=TOOL) is None                  # the refusal did not spend the grant


# ---- bounded waits, no leaks -----------------------------------------------------------------------------------

def test_locked_db_refuses_within_a_bound_and_releases(db, monkeypatch):
    mint_grant(db, "g-lock", tools=[TOOL])
    monkeypatch.setattr(cr, "DB_TIMEOUT_S", 0.5)
    holder = sqlite3.connect(db)
    holder.execute("BEGIN EXCLUSIVE")
    try:
        t0 = time.monotonic()
        reason = cr.redeem_capability("g-lock", tool=TOOL)
        assert reason is not None and time.monotonic() - t0 < 10.0
    finally:
        holder.rollback()
        holder.close()
    assert cr.redeem_capability("g-lock", tool=TOOL) is None                 # grant intact, DB not left locked


def test_audit_write_failure_refuses_and_keeps_the_grant(db, monkeypatch):
    from aiosh_mcp import audit_client
    mint_grant(db, "g-audit", tools=[TOOL])
    real = audit_client.write_audit_row
    monkeypatch.setattr(audit_client, "write_audit_row", lambda *a, **k: (_ for _ in ()).throw(OSError("ring")))
    assert cr.redeem_capability("g-audit", tool=TOOL) is not None
    monkeypatch.setattr(audit_client, "write_audit_row", real)
    assert cr.redeem_capability("g-audit", tool=TOOL) is None                # rolled back: still redeemable once


def test_single_use_grant_survives_a_race(db):
    mint_grant(db, "g-race", tools=[TOOL])
    results, start = [], threading.Barrier(12)

    def worker():
        start.wait()
        results.append(cr.redeem_capability("g-race", tool=TOOL))
    threads = [threading.Thread(target=worker) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert len(results) == 12 and results.count(None) == 1
    with closing(sqlite3.connect(db)) as c:
        assert c.execute("SELECT count(*) FROM audit_ring WHERE tool='pep.capability.redeem'").fetchone()[0] == 1


def test_failure_announcement_is_once_per_surface_under_concurrency(db, monkeypatch, capsys):
    monkeypatch.setattr(trs, "service", lambda: (_ for _ in ()).throw(KeyError("x")))
    start = threading.Barrier(16)

    def worker(surface):
        start.wait()
        for _ in range(25):
            pol.evaluate("t", surface=surface)
    threads = [threading.Thread(target=worker, args=(pol.SURFACES[i % 2],)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    err = capsys.readouterr().err
    assert err.count("unavailable in dispatch") == 1 and err.count("unavailable in the agent loop") == 1


# ---- honest audit on the fail-closed path (ADR-0035 F-2) ---------------------------------------------------------

def test_strict_registry_failure_writes_an_honest_refusal_row(db, monkeypatch):
    from aiosh_mcp import _dispatch, audit_client
    strict(monkeypatch)
    monkeypatch.setattr(trs, "service", lambda: (_ for _ in ()).throw(RuntimeError("catalog gone")))
    verdict, row = _dispatch.dispatch(tool="aios.process.list", command="ps", args={}, target=None,
                                      grant_id=None, require_grant=False)
    assert verdict["ok"] is False and verdict["gate"] == "pep"
    assert verdict["reason"].endswith("(tool registry unavailable, strict: fail closed)")
    with closing(audit_client.open_db(db)) as c:
        last = c.execute("SELECT outcome, outcome_detail FROM audit_ring ORDER BY rowid DESC LIMIT 1").fetchone()
    assert last["outcome"] != "ok" and "tool registry unavailable, strict: fail closed" in (last["outcome_detail"] or "")
