"""Scaffold tests for the Agent Loop Hardening CLI surface (T-03285)."""

import pytest

from aiosh_mcp import agent_loop_cli
from aiosh_mcp.agent_loop_cli import (
    EXIT_FAILURE,
    EXIT_SUCCESS,
    EXIT_TIMEOUT,
    EXIT_UNAUTHORIZED,
    EXIT_USAGE,
    MAX_PLAN_TURNS,
    CliResult,
    PlanTurn,
)
from aiosh_mcp.agent_loop_service import AgentLoopService


def test_exit_code_taxonomy_matches_spec():
    assert (EXIT_SUCCESS, EXIT_FAILURE, EXIT_USAGE, EXIT_UNAUTHORIZED, EXIT_TIMEOUT) == (0, 1, 2, 3, 4)
    assert MAX_PLAN_TURNS == 100  # LoopConfig.max_iterations upper bound


def test_plan_turn_defaults():
    t = PlanTurn(action_intent="x")
    assert (t.tool_name, t.tool_args, t.tokens_consumed, t.policy_allowed) == (None, None, 0, True)


@pytest.mark.parametrize(
    "call",
    [
        lambda: agent_loop_cli.load_plan("plan.json"),
        lambda: agent_loop_cli.dispatch_cli(["validate", "--plan", "plan.json"]),
        lambda: agent_loop_cli.render(CliResult(exit_code=0, subcommand="validate"), json_mode=True),
        lambda: agent_loop_cli.main(["validate", "--plan", "plan.json"]),
        lambda: CliResult(exit_code=0, subcommand="run").to_dict(),
    ],
)
def test_stubs_fail_loudly(call):
    with pytest.raises(NotImplementedError):
        call()


def test_service_complete_loop_stub():
    with pytest.raises(NotImplementedError):
        AgentLoopService().complete_loop("loop-scaffold-cli", capability_token="t")
