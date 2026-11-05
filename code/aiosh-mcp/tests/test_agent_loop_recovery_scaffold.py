"""Scaffold tests for agent-loop recovery & validation (T-03355)."""

import pytest

from aiosh_mcp import agent_loop_recovery as rec


def test_constants():
    assert rec.RECOVER_TOOL == "aios.agent_loop.recover"
    assert set(rec.TERMINAL_EVENTS) == {"abort", "complete", "timeout", "failed", "recovered"}
    assert "step_index_gap" in rec.PROBLEM_KINDS and rec.DEFAULT_GRACE_S == 900


@pytest.mark.parametrize("call", [lambda: rec.validate_ring(None), lambda: rec.recover_orphans(None, "t")])
def test_stubs_fail_loudly(call):
    with pytest.raises(NotImplementedError):
        call()
