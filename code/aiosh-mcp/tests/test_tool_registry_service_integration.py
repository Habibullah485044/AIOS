"""Integration tests for the tool registry core service (T-03378): wired into dispatch and the agent-loop policy.

Shadow mode (default) must change nothing (TOOLSVC-INV2); strict mode may only tighten (TOOLSVC-INV5);
neither adds audit rows (TOOLSVC-INV3); a broken registry falls back to the legacy rules.
"""

import json
from contextlib import closing

import pytest

from aiosh_mcp import _dispatch, audit_client
from aiosh_mcp import tool_registry_service as trs
from aiosh_mcp.agent_loop_policy import evaluate_step


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path))
    monkeypatch.setattr(trs, "_SERVICE", None)              # fresh singleton per test (mode is read at build)
    monkeypatch.setattr(trs, "_SERVICE_ERROR", None)
    monkeypatch.setattr(trs, "_REPORTED", set())
    monkeypatch.setattr(trs, "_REPORT_STATE", {"lines": 0, "suppressed": 0})
    return tmp_path


def rows():
    with closing(audit_client.open_db()) as conn:
        return [r.outcome for r in audit_client.tail(conn, 1000)]


def call(tool, target="/tmp/x", grant_id=None, require_grant=False):
    verdict, _ = _dispatch.dispatch(tool=tool, command=f"{tool} demo", args={"x": 1}, target=target,
                                    grant_id=grant_id, require_grant=require_grant)
    return verdict


def disagreement_lines(err):
    return [json.loads(line) for line in err.splitlines() if trs.LOG_EVENT in line]


def test_shadow_changes_nothing_and_reports(home, capsys, monkeypatch):
    monkeypatch.delenv(trs.ENV_MODE, raising=False)
    v = call("aios.mystery.read")                           # unregistered; legacy: no grant needed
    assert v["ok"] is True and rows() == []                 # same verdict; an allowed call is audited by commit()
    lines = disagreement_lines(capsys.readouterr().err)
    assert lines and lines[0]["surface"] == "dispatch" and "unregistered" in lines[0]["disagreements"]
    v = call("aios.process.list", target=None)               # registered and in agreement: silent
    assert v["ok"] is True and disagreement_lines(capsys.readouterr().err) == []


def test_strict_only_tightens_dispatch(home, monkeypatch):
    monkeypatch.setenv(trs.ENV_MODE, "strict")
    v = call("aios.mystery.read")                           # unregistered ⇒ fail closed: grant required
    assert v["ok"] is False and "requires explicit PEP grant" in v["reason"]
    assert rows() == ["refused"]                             # a refusal is still exactly one audit row
    assert call("aios.process.list", target=None)["ok"] is True                  # registered read-only: unchanged


def test_broken_registry_falls_back_to_legacy(home, capsys, monkeypatch):
    def boom():
        raise RuntimeError("catalog exploded")
    monkeypatch.setattr(trs, "service", boom)
    monkeypatch.setattr(_dispatch, "_REGISTRY_FAILURE_LOGGED", False)
    assert call("aios.mystery.read")["ok"] is True and call("aios.mystery.read")["ok"] is True
    err = capsys.readouterr().err
    assert err.count("tool registry unavailable in dispatch") == 1            # logged once
    assert rows() == []                                      # allowed, as before; no extra rows


def test_agent_loop_step_shadow_and_strict(home, monkeypatch):
    monkeypatch.delenv(trs.ENV_MODE, raising=False)
    shadow = evaluate_step("aios.mystery.read", ["/tmp/x"], {"path": "/tmp/x"})
    assert shadow.irreversible is False                      # legacy decision unchanged
    monkeypatch.setattr(trs, "_SERVICE", None)
    monkeypatch.setenv(trs.ENV_MODE, "strict")
    from aiosh_mcp.tool_registry_config import reset_process_config
    reset_process_config()                                   # config is resolved once per process (T-03409)
    strict = evaluate_step("aios.mystery.read", ["/tmp/x"], {"path": "/tmp/x"})
    assert strict.irreversible is True                       # unregistered counts against the budget in strict
    assert evaluate_step("pentest.nmap", ["10.0.0.5"], {"target": "10.0.0.5"}).irreversible is True


def test_reasoning_steps_are_untouched(home):
    assert evaluate_step(None, None, {}).irreversible is False    # no tool: the registry is not consulted
