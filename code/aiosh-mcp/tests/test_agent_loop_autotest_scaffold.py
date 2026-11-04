"""Scaffold tests for the agent-loop automated test battery (T-03315)."""

import random

import pytest

import agent_loop_model as m


def test_interfaces_exist():
    assert set(m.OP_KINDS) == {"start", "advance", "abort", "complete", "revoke", "snapshot"}
    assert m.FuzzReport(seed=1, ops_run=0).ok is True
    assert m.Expectation(error_code=None).audit_tools == ()
    assert m.Op("start", "loop-x-00000001").args == {}


@pytest.mark.parametrize("call", [
    lambda: m.LoopModel().expect(m.Op("start", "loop-x-00000001")),
    lambda: m.LoopModel().apply(m.Op("start", "loop-x-00000001"), None),
    lambda: m.generate_ops(random.Random(1), 5, m.LoopModel()),
    lambda: m.run_and_check(1, 5, "unused.db"),
])
def test_stubs_fail_loudly(call):
    with pytest.raises(NotImplementedError):
        call()
