"""Implementation tests for the Agent Loop Hardening CLI surface (T-03286)."""

import json

import pytest

from agent_loop_grants import audit_tools, mint_grant
from aiosh_mcp.agent_loop_cli import EXIT_SUCCESS, EXIT_UNAUTHORIZED, EXIT_USAGE, dispatch_cli, main
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_service import AgentLoopService


@pytest.fixture
def env(tmp_path):
    db = str(tmp_path / "audit.db")
    mint_grant(db, "gr_cli_impl", tools=["aios.agent_loop.start", "aios.fs.read"])
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"turns": [
        {"action_intent": "read README", "tool_name": "aios.fs.read",
         "tool_args": {"path": "README.md"}, "tokens_consumed": 120},
        {"action_intent": "write file", "tool_name": "fs.write"},
    ]}), encoding="utf-8")
    svc = AgentLoopService(gate=PepCapabilityGate(db))
    return db, str(plan), svc


def test_run_executes_plan_and_completes(env):
    db, plan, svc = env
    res = dispatch_cli(["run", "--loop-id", "loop-cli-impl-01", "--token", "gr_cli_impl", "--plan", plan],
                       service=svc, db_path=db)
    assert res.exit_code == EXIT_SUCCESS
    assert res.data["final_state"] == "COMPLETED"
    assert [t["outcome"] for t in res.data["turns"]] == ["ok", "refused"]
    assert res.data["refused"] == 1
    assert [t for t, _ in audit_tools(db)] == [
        "pep.capability.redeem", "aios.agent_loop.start", "aios.agent_loop.step",
        "aios.agent_loop.step", "aios.agent_loop.complete",
    ]


def test_history_reads_audit_ring(env):
    db, plan, svc = env
    dispatch_cli(["run", "--loop-id", "loop-cli-impl-02", "--token", "gr_cli_impl", "--plan", plan],
                 service=svc, db_path=db)
    res = dispatch_cli(["history", "--loop-id", "loop-cli-impl-02"], db_path=db)
    assert res.exit_code == EXIT_SUCCESS
    assert [e["tool"] for e in res.data["events"]] == [
        "aios.agent_loop.start", "aios.agent_loop.step", "aios.agent_loop.step", "aios.agent_loop.complete",
    ]
    assert dispatch_cli(["history", "--loop-id", "loop-cli-other-99"], db_path=db).data["events"] == []


def test_validate_and_unauthorized(env):
    db, plan, svc = env
    assert dispatch_cli(["validate", "--plan", plan]).data == {"turns": 2}
    res = dispatch_cli(["run", "--loop-id", "loop-cli-impl-03", "--token", "forged", "--plan", plan],
                       service=svc, db_path=db)
    assert res.exit_code == EXIT_UNAUTHORIZED
    assert res.error_code == "LOOPSERV_ERR_UNAUTHORIZED"


def test_main_json_output_matches_exit_code(env, capsys):
    db, plan, svc = env
    code = main(["validate", "--plan", plan, "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == payload["exit_code"] == EXIT_SUCCESS
    assert payload == {"ok": True, "exit_code": 0, "subcommand": "validate", "data": {"turns": 2}}
    assert main(["bogus"]) == EXIT_USAGE


def test_service_complete_loop(env):
    db, plan, svc = env
    from aiosh_mcp.agent_loop_data_model import LoopConfig, LoopState
    svc.start_loop(LoopConfig(loop_id="loop-cli-impl-04"), capability_token="gr_cli_impl")
    snap = svc.complete_loop("loop-cli-impl-04", capability_token="gr_cli_impl")
    assert snap.current_state == LoopState.COMPLETED
    assert svc.list_active_loops() == []
