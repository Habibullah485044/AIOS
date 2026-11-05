"""Scaffold tests for agent-loop observability (T-03335)."""

from aiosh_mcp import agent_loop_observability as obs


def test_constants_and_library_logger():
    assert obs.logger.name == "aiosh_mcp.agent_loop"
    assert obs.logger.handlers == []          # library rule: no handlers added
    assert obs.HEALTH_STATES == ("ok", "degraded", "failing")
    assert "constitution" in obs.REFUSAL_REASONS and obs.MAX_WINDOW == 100_000
