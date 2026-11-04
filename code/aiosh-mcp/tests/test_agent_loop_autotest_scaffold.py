"""Scaffold tests for the agent-loop automated test battery (T-03315)."""

import agent_loop_model as m


def test_interfaces_exist():
    assert set(m.OP_KINDS) == {"start", "advance", "abort", "complete", "revoke", "snapshot", "foreign_start"}
    assert m.FuzzReport(seed=1, ops_run=0).ok is True
    assert m.Expectation(error_code=None).audit_tools == ()
    assert m.Op("start", "loop-x-00000001").args == {}
