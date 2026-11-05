"""Scaffold tests for agent-loop observability (T-03335)."""

import logging

import pytest

from agent_loop_grants import AllowAllGate
from aiosh_mcp import agent_loop_observability as obs
from aiosh_mcp.agent_loop_service import AgentLoopService


def test_constants_and_library_logger():
    assert obs.logger.name == "aiosh_mcp.agent_loop"
    assert obs.logger.handlers == []          # library rule: no handlers added
    assert obs.HEALTH_STATES == ("ok", "degraded", "failing")
    assert "constitution" in obs.REFUSAL_REASONS and obs.MAX_WINDOW == 100_000


@pytest.mark.parametrize("call", [
    lambda: obs.classify_refusal("x"),
    lambda: obs.ring_metrics(None, 10),
    lambda: obs.health({}),
    lambda: obs.log_event("start", "loop-obs-0001", None, "ok"),
    lambda: AgentLoopService(gate=AllowAllGate()).stats(),
])
def test_stubs_fail_loudly(call):
    with pytest.raises(NotImplementedError):
        call()
