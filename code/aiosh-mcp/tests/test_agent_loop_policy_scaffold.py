"""Scaffold tests for the agent-loop security policy (T-03325)."""

import pytest

from aiosh_mcp import agent_loop_policy as pol


def test_interfaces_and_constants():
    assert pol.StepPolicy().refused_reason is None and pol.StepPolicy().irreversible is False
    assert pol.LOOPPOL_ERR_CONSTITUTION == "LOOPPOL_ERR_CONSTITUTION"
    assert set(pol.IRREVERSIBLE_TOOLS) == {"system.reboot", "system.shutdown"}


@pytest.mark.parametrize("call", [
    lambda: pol.is_irreversible("fs.write", {}),
    lambda: pol.evaluate_step("fs.write", "/tmp/x", {}),
])
def test_stubs_fail_loudly(call):
    with pytest.raises(NotImplementedError):
        call()
