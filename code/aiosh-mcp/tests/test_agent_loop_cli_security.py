"""Security tests for the Agent Loop Hardening CLI surface (T-03289).

One test per abuse scenario in docs/tasks/evidence/T-03289-security.md.
"""

import io
import json

import pytest

from agent_loop_grants import audit_tools, mint_grant
from aiosh_mcp.agent_loop_cli import (
    EXIT_SUCCESS,
    EXIT_UNAUTHORIZED,
    EXIT_USAGE,
    MAX_PLAN_BYTES,
    dispatch_cli,
    load_plan,
    render,
    PlanError,
)
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_service import AgentLoopService

PLAN = {"turns": [{"action_intent": "read", "tool_name": "aios.fs.read",
                   "tool_args": {"note": "\x1b[2J\x1b]0;pwned\x07", "auth": "Bearer sk-abcdefghijklmnopqrstuvwxyz0123"}}]}


@pytest.fixture
def env(tmp_path):
    db = str(tmp_path / "audit.db")
    mint_grant(db, "gr_cli_sec", tools=["aios.agent_loop.start", "aios.fs.read"])
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps(PLAN), encoding="utf-8")
    return db, str(plan), AgentLoopService(gate=PepCapabilityGate(db))


def _run(env, *token_args, loop_id="loop-cli-sec-01"):
    db, plan, svc = env
    return dispatch_cli(["run", "--loop-id", loop_id, "--plan", plan, *token_args], service=svc, db_path=db)


def test_c1_token_from_env_keeps_grant_out_of_argv(env, monkeypatch):
    monkeypatch.setenv("AIOS_LOOP_GRANT", "gr_cli_sec")
    res = _run(env, "--token-env", "AIOS_LOOP_GRANT")
    assert res.exit_code == EXIT_SUCCESS
    assert res.data["final_state"] == "COMPLETED"


def test_c1_token_from_stdin(env, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("gr_cli_sec\n"))
    assert _run(env, "--token-stdin").exit_code == EXIT_SUCCESS


def test_c1_unset_env_var_is_unauthorized_not_a_crash(env, monkeypatch):
    monkeypatch.delenv("AIOS_LOOP_GRANT_MISSING", raising=False)
    res = _run(env, "--token-env", "AIOS_LOOP_GRANT_MISSING")
    assert res.exit_code == EXIT_UNAUTHORIZED
    assert audit_tools(env[0]) == []


def test_c1_token_sources_are_mutually_exclusive(env):
    assert _run(env, "--token", "gr_cli_sec", "--token-stdin").exit_code == EXIT_USAGE
    assert _run(env).exit_code == EXIT_USAGE


def test_c2_overlong_token_rejected(env):
    assert _run(env, "--token", "g" * 257).exit_code == EXIT_USAGE


def test_c3_forged_token_cannot_run(env):
    res = _run(env, "--token", "gr_forged")
    assert res.exit_code == EXIT_UNAUTHORIZED
    assert audit_tools(env[0]) == []


def test_c4_growing_file_is_read_bounded(tmp_path, monkeypatch):
    """Oversized content is rejected by the bounded read itself (the stat() pre-check was removed).

    The stat/read race is closed by construction (read at most MAX_PLAN_BYTES + 1 bytes);
    this test pins the bound, it does not simulate a concurrently growing file.
    """
    p = tmp_path / "grow.json"
    p.write_bytes(b" " * (MAX_PLAN_BYTES + 10))
    with pytest.raises(PlanError, match="exceeds"):
        load_plan(str(p))


def test_c5_deeply_nested_json_is_a_plan_error(tmp_path):
    p = tmp_path / "deep.json"
    p.write_text("[" * 200000, encoding="utf-8")
    res = dispatch_cli(["validate", "--plan", str(p)])
    assert res.exit_code == EXIT_USAGE
    assert res.error_code == "LOOPCLI_ERR_PLAN"


def test_c6_non_regular_plan_paths_rejected(tmp_path):
    assert dispatch_cli(["validate", "--plan", str(tmp_path)]).exit_code == EXIT_USAGE


def test_c7_no_terminal_escapes_or_secrets_in_output(env, monkeypatch):
    monkeypatch.setenv("AIOS_LOOP_GRANT", "gr_cli_sec")
    res = _run(env, "--token-env", "AIOS_LOOP_GRANT")
    for json_mode in (False, True):
        out = render(res, json_mode=json_mode)
        assert "\x1b" not in out and "\x07" not in out
        assert "sk-abcdefghijklmnop" not in out
    hist = dispatch_cli(["history", "--loop-id", "loop-cli-sec-01"], db_path=env[0])
    for json_mode in (False, True):
        out = render(hist, json_mode=json_mode)
        assert "\x1b" not in out
        assert "sk-abcdefghijklmnop" not in out


def test_c8_history_sql_injection_is_inert(env, monkeypatch):
    monkeypatch.setenv("AIOS_LOOP_GRANT", "gr_cli_sec")
    _run(env, "--token-env", "AIOS_LOOP_GRANT")
    res = dispatch_cli(["history", "--loop-id", "x' OR '1'='1"], db_path=env[0])
    assert res.exit_code == EXIT_SUCCESS
    assert res.data["events"] == []
