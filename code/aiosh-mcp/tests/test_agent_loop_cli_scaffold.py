"""Scaffold tests for the Agent Loop Hardening CLI surface (T-03285)."""

from aiosh_mcp.agent_loop_cli import (
    EXIT_FAILURE,
    EXIT_SUCCESS,
    EXIT_TIMEOUT,
    EXIT_UNAUTHORIZED,
    EXIT_USAGE,
    MAX_PLAN_TURNS,
    PlanTurn,
)


def test_exit_code_taxonomy_matches_spec():
    assert (EXIT_SUCCESS, EXIT_FAILURE, EXIT_USAGE, EXIT_UNAUTHORIZED, EXIT_TIMEOUT) == (0, 1, 2, 3, 4)
    assert MAX_PLAN_TURNS == 100  # LoopConfig.max_iterations upper bound


def test_plan_turn_defaults():
    t = PlanTurn(action_intent="x")
    assert (t.tool_name, t.tool_args, t.tokens_consumed, t.policy_allowed) == (None, None, 0, True)
