"""Hardening tests for the Agent Loop Hardening CLI surface (T-03290)."""

import json
import sqlite3

import pytest

from agent_loop_grants import AllowAllGate, audit_tools, mint_grant
from aiosh_mcp.agent_loop_cli import (
    EXIT_FAILURE,
    EXIT_INTERRUPTED,
    EXIT_SUCCESS,
    dispatch_cli,
    main,
)
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_service import AgentLoopService


def _plan(tmp_path, n=3):
    p = tmp_path / "plan.json"
    p.write_text(json.dumps({"turns": [{"action_intent": f"t{i}", "tool_name": "aios.fs.read"}
                                       for i in range(n)]}), encoding="utf-8")
    return str(p)


class InterruptOnSecondTool(AllowAllGate):
    def __init__(self, exc):
        super().__init__()
        self.calls = 0
        self.exc = exc

    def tool_refusal(self, grant_id, tool_name):
        self.calls += 1
        if self.calls == 2:
            raise self.exc
        return None


def test_keyboard_interrupt_writes_honest_abort_row(tmp_path):
    """Gate errors are fail-closed refusals; a KeyboardInterrupt must still end the loop audited."""
    gate = InterruptOnSecondTool(KeyboardInterrupt())
    svc = AgentLoopService(gate=gate)
    res = dispatch_cli(["run", "--loop-id", "loop-cli-hard-int", "--token", "t", "--plan", _plan(tmp_path)],
                       service=svc)
    assert res.exit_code == EXIT_INTERRUPTED
    assert res.error_code == "LOOPCLI_ERR_INTERRUPTED"
    assert svc.get_snapshot("loop-cli-hard-int").current_state.value == "ABORTED"
    assert gate.events[-1] == ("abort", "loop-cli-hard-int", "ok")


def test_unexpected_crash_writes_honest_abort_row(tmp_path, monkeypatch):
    gate = AllowAllGate()
    svc = AgentLoopService(gate=gate)
    real = svc.advance_turn
    calls = {"n": 0}

    def crashing(*a, **k):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("tool adapter exploded")
        return real(*a, **k)

    monkeypatch.setattr(svc, "advance_turn", crashing)
    res = dispatch_cli(["run", "--loop-id", "loop-cli-hard-crash", "--token", "t", "--plan", _plan(tmp_path)],
                       service=svc)
    assert res.exit_code == EXIT_FAILURE
    assert res.error_code == "LOOPCLI_ERR_INTERNAL"
    assert gate.events[-1] == ("abort", "loop-cli-hard-crash", "ok")


def test_interrupted_run_abort_row_in_real_ring(tmp_path, monkeypatch):
    db = str(tmp_path / "audit.db")
    mint_grant(db, "gr_cli_hard", tools=["aios.agent_loop.start", "aios.fs.read"])
    gate = PepCapabilityGate(db)
    real = gate.tool_refusal
    calls = {"n": 0}

    def flaky(grant_id, tool_name):
        calls["n"] += 1
        if calls["n"] == 2:
            raise KeyboardInterrupt
        return real(grant_id, tool_name)

    monkeypatch.setattr(gate, "tool_refusal", flaky)
    res = dispatch_cli(["run", "--loop-id", "loop-cli-hard-real", "--token", "gr_cli_hard",
                        "--plan", _plan(tmp_path)], service=AgentLoopService(gate=gate), db_path=db)
    assert res.exit_code == EXIT_INTERRUPTED
    hist = dispatch_cli(["history", "--loop-id", "loop-cli-hard-real"], db_path=db).data["events"]
    assert [e["tool"] for e in hist][-1] == "aios.agent_loop.abort"
    assert "KeyboardInterrupt" in hist[-1]["outcome_detail"]


def test_history_on_db_without_audit_table(tmp_path):
    db = tmp_path / "other.db"
    sqlite3.connect(db).execute("CREATE TABLE unrelated (x)").connection.close()
    res = dispatch_cli(["history", "--loop-id", "loop-cli-hard-01"], db_path=str(db))
    assert res.exit_code == EXIT_SUCCESS
    assert res.data["events"] == []


def test_history_on_corrupt_db_is_explicit_error(tmp_path):
    db = tmp_path / "corrupt.db"
    db.write_bytes(b"this is not a sqlite database" * 100)
    res = dispatch_cli(["history", "--loop-id", "loop-cli-hard-01"], db_path=str(db))
    assert res.exit_code == EXIT_FAILURE
    assert res.error_code == "LOOPCLI_ERR_AUDIT_READ"


def test_history_does_not_modify_db(tmp_path):
    db = str(tmp_path / "audit.db")
    mint_grant(db, "gr_cli_hard_ro")
    before = (tmp_path / "audit.db").read_bytes()
    dispatch_cli(["history", "--loop-id", "loop-cli-hard-01"], db_path=db)
    assert (tmp_path / "audit.db").read_bytes() == before


def test_main_survives_broken_pipe(tmp_path, monkeypatch):
    class ClosedPipe:
        def write(self, _):
            raise BrokenPipeError

        def flush(self):
            raise BrokenPipeError

        def fileno(self):
            raise ValueError("no fd")

    monkeypatch.setattr("sys.stdout", ClosedPipe())
    p = tmp_path / "plan.json"
    p.write_text(json.dumps({"turns": [{"action_intent": "x"}]}), encoding="utf-8")
    assert main(["validate", "--plan", str(p)]) == EXIT_SUCCESS


def test_audit_rows_unchanged_on_success(tmp_path):
    db = str(tmp_path / "audit.db")
    mint_grant(db, "gr_cli_hard_ok", tools=["aios.agent_loop.start", "aios.fs.read"])
    res = dispatch_cli(["run", "--loop-id", "loop-cli-hard-ok", "--token", "gr_cli_hard_ok",
                        "--plan", _plan(tmp_path, 2)], service=AgentLoopService(gate=PepCapabilityGate(db)))
    assert res.exit_code == EXIT_SUCCESS
    assert [t for t, _ in audit_tools(db)].count("aios.agent_loop.abort") == 0
