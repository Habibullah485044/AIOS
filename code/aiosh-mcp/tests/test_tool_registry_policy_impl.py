"""Targeted tests for the tool registry security policy implementation (T-03426; spec T-03424)."""

import pytest

from aiosh_mcp import tool_registry_policy as pol
from aiosh_mcp import tool_registry_service as trs
from aiosh_mcp.tool_registry_data_model import ToolCatalog, default_catalog


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path))
    monkeypatch.delenv(trs.ENV_MODE, raising=False)
    return tmp_path


def strict(monkeypatch):
    """The mode is fixed per process at first use, so switching needs a fresh process state."""
    from aiosh_mcp import tool_registry_config
    monkeypatch.setenv(trs.ENV_MODE, "strict")
    tool_registry_config.reset_process_config()
    monkeypatch.setattr(trs, "_SERVICE", None)
    pol.reset_process_state()


def test_revision_shape_and_determinism():
    rev = pol.policy_revision()
    assert rev.startswith("trp-") and len(rev) == 4 + pol.REVISION_HEX_LEN
    assert rev == pol.policy_revision(default_catalog()) == pol.policy_revision(ToolCatalog(default_catalog().entries()))


def test_strict_catalog_grant_is_attributed(monkeypatch):
    strict(monkeypatch)
    v = pol.evaluate("aios.anchor.create", surface="dispatch")           # catalog: grant; legacy name rule: none
    assert v.requires_grant and v.registry_added_grant and v.failure is None and v.mode == "strict"
    assert pol.grant_reason_suffix(v) == f" (tool registry strict, catalog {pol.policy_revision()})"


def test_shadow_adds_nothing():
    v = pol.evaluate("aios.anchor.create", surface="dispatch")
    assert (v.requires_grant, v.registry_added_grant, v.mode) == (False, False, "shadow")
    assert pol.grant_reason_suffix(v) == ""


def test_caller_grant_is_not_attributed_to_the_registry(monkeypatch):
    strict(monkeypatch)
    v = pol.evaluate("aios.anchor.create", surface="dispatch", require_grant=True)
    assert v.requires_grant and not v.registry_added_grant and pol.grant_reason_suffix(v) == ""


def test_strict_marks_catalog_irreversible_in_the_agent_loop(monkeypatch):
    assert pol.evaluate("aios.backup.create", surface="agent_loop").irreversible is False
    strict(monkeypatch)
    assert pol.evaluate("aios.backup.create", surface="agent_loop").irreversible is True


def test_failure_fails_closed_only_when_strict(monkeypatch, capsys):
    def boom():
        raise RuntimeError("catalog exploded")
    monkeypatch.setattr(trs, "service", boom)
    v = pol.evaluate("aios.x", surface="dispatch")
    assert (v.requires_grant, v.failure) == (False, "RuntimeError")
    strict(monkeypatch)
    monkeypatch.setattr(trs, "service", boom)
    v = pol.evaluate("aios.x", surface="dispatch")
    assert v.requires_grant and v.irreversible and v.registry_added_grant and v.failure == "RuntimeError"
    assert pol.grant_reason_suffix(v) == " (tool registry unavailable, strict: fail closed)"
    assert "tool registry unavailable in dispatch (RuntimeError); strict: grants required" in capsys.readouterr().err


def test_bad_surface_is_a_programming_error():
    with pytest.raises(ValueError):
        pol.evaluate("aios.fs.read", surface="cli")


def test_stats_report_the_revision():
    from aiosh_mcp.server import mcp
    from aiosh_mcp.tool_registry_api import STATS_TOOL
    tool = {t.name: t for t in mcp._tool_manager.list_tools()}[STATS_TOOL]
    out = tool.fn()
    assert out["ok"] and out["data"]["policy_revision"] == pol.policy_revision()


def test_dispatch_refusal_names_the_registry(monkeypatch):
    from aiosh_mcp import _dispatch
    strict(monkeypatch)
    verdict, row = _dispatch.dispatch(tool="aios.anchor.create", command="anchor create", args={}, target=None,
                                      grant_id=None, require_grant=False)
    assert verdict["ok"] is False and verdict["gate"] == "pep"
    assert verdict["reason"] == ("tool 'aios.anchor.create' requires explicit PEP grant"
                                 f" (tool registry strict, catalog {pol.policy_revision()})")
