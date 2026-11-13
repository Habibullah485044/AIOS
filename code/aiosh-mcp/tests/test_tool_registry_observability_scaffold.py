"""Scaffold checks for tool registry observability (T-03435; spec T-03434)."""

import pytest

from aiosh_mcp import capability_redeem as cr
from aiosh_mcp import tool_registry_observability as obs
from aiosh_mcp import tool_registry_policy as pol


def test_interface_exists():
    assert (obs.DEFAULT_WINDOW, obs.MAX_WINDOW, obs.DEFAULT_QUERY_DEADLINE_S) == (10_000, 100_000, 10.0)
    assert obs.HEALTH_STATES == ("ok", "degraded", "failing")
    assert (obs.TOOLOBS_ERR_WINDOW, obs.TOOLOBS_ERR_READ) == ("TOOLOBS_ERR_WINDOW", "TOOLOBS_ERR_READ")
    assert obs.MAX_TOOL_KEYS == 64 and pol.MAX_FAILURE_TYPES == 16
    assert len(cr.REFUSAL_CLASSES) == 8 and cr.REFUSAL_CLASSES[-1] == "other"
    assert cr.LOGGER_NAME == "aiosh_mcp.capability"


def test_markers_match_the_policy_suffixes():
    strict = pol.grant_reason_suffix(pol.PolicyVerdict(True, False, True, "strict", "trp-x"))
    failed = pol.grant_reason_suffix(pol.PolicyVerdict(True, True, True, "strict", "", failure="E"))
    assert obs.STRICT_MARKER in strict and obs.UNAVAILABLE_MARKER in failed


@pytest.mark.parametrize("call", [lambda: obs.ring_metrics(), lambda: obs.health({}), lambda: pol.policy_stats(),
                                  lambda: cr.classify_refusal("x"), lambda: cr.capability_stats(),
                                  lambda: cr.reset_stats()])
def test_stubs_fail_loudly(call):
    with pytest.raises(NotImplementedError):
        call()


def test_live_paths_do_not_call_the_stubs(tmp_path, monkeypatch):
    """The scaffold stays off the production path: stats and the gate still work."""
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path))
    from aiosh_mcp.server import mcp
    tools = {t.name: t for t in mcp._tool_manager.list_tools()}
    assert tools["aios_tool_registry_stats"].fn()["ok"] is True
    assert cr.redeem_capability("forged", tool="aios.mcp.recovery.repair") is not None
