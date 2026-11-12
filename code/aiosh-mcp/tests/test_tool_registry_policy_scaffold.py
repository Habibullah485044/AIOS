"""Scaffold checks for the tool registry security policy module (T-03425; spec T-03424)."""

import dataclasses

import pytest

from aiosh_mcp import tool_registry_policy as pol


def test_interface_exists():
    assert pol.SURFACES == ("dispatch", "agent_loop")
    assert pol.SECURITY_FIELDS == ("effect", "irreversible", "requires_grant", "scope_kind", "open_world")
    fields = [f.name for f in dataclasses.fields(pol.PolicyVerdict)]
    assert fields == ["requires_grant", "irreversible", "registry_added_grant", "mode", "revision", "failure"]


def test_verdict_is_immutable():
    v = pol.PolicyVerdict(True, False, True, "strict", "trp-0")
    with pytest.raises(dataclasses.FrozenInstanceError):
        v.requires_grant = False


@pytest.mark.parametrize("call", [
    lambda: pol.policy_revision(),
    lambda: pol.evaluate("aios.fs.read", surface="dispatch"),
    lambda: pol.grant_reason_suffix(pol.PolicyVerdict(True, False, True, "strict", "trp-0")),
])
def test_stubs_fail_loudly(call):
    with pytest.raises(NotImplementedError, match="T-03426"):
        call()


def test_no_consumer_wired_yet():
    """Until T-03426 the stubs must not sit on a production path (dispatch and the agent loop would raise)."""
    from pathlib import Path
    import aiosh_mcp
    root = Path(aiosh_mcp.__file__).parent
    for name in ("_dispatch.py", "agent_loop_policy.py"):
        assert "tool_registry_policy" not in (root / name).read_text(encoding="utf-8"), name
