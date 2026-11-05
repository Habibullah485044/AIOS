"""Scaffold tests for agent-loop recovery & validation (T-03355)."""

from aiosh_mcp import agent_loop_recovery as rec


def test_constants():
    assert rec.RECOVER_TOOL == "aios.agent_loop.recover"
    assert set(rec.TERMINAL_EVENTS) == {"abort", "complete", "timeout", "failed", "recovered"}
    assert "step_index_gap" in rec.PROBLEM_KINDS and rec.DEFAULT_GRACE_S == 900
