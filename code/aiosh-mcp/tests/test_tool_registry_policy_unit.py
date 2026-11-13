"""Unit tests for the tool registry security policy (T-03427; spec T-03424 §6)."""

import dataclasses
import itertools

import pytest

from aiosh_mcp import tool_registry_config
from aiosh_mcp import tool_registry_policy as pol
from aiosh_mcp import tool_registry_service as trs
from aiosh_mcp.tool_registry_data_model import Effect, ScopeKind, ToolCatalog, default_catalog


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path))
    monkeypatch.delenv(trs.ENV_MODE, raising=False)


def set_mode(monkeypatch, mode):
    if mode == "strict":
        monkeypatch.setenv(trs.ENV_MODE, "strict")
    else:
        monkeypatch.delenv(trs.ENV_MODE, raising=False)
    tool_registry_config.reset_process_config()
    monkeypatch.setattr(trs, "_SERVICE", None)
    pol.reset_process_state()


# ---- policy_revision (TOOLPOL-INV5) ---------------------------------------------------------------------------

def _with(entry_index, **changes):
    entries = list(default_catalog().entries())
    entries[entry_index] = dataclasses.replace(entries[entry_index], **changes)
    return ToolCatalog(entries)


def _index(name):
    return next(i for i, e in enumerate(default_catalog().entries()) if e.canonical == name)


BASE = pol.policy_revision()


@pytest.mark.parametrize("changes", [
    {"effect": Effect.DESTRUCTIVE, "idempotent": False},
    {"irreversible": True, "requires_grant": True, "effect": Effect.ADDITIVE},
    {"requires_grant": True},
    {"scope_kind": ScopeKind.PATH},
    {"open_world": True},
])
def test_any_security_field_change_changes_the_revision(changes):
    i = _index("aios.process.list")                     # read-only, no grant, no scope, closed world
    assert pol.policy_revision(_with(i, **changes)) != BASE


@pytest.mark.parametrize("changes", [{"title": "List running processes"}, {"mcp_names": ("aios_process_list", "ps")}])
def test_non_security_field_change_keeps_the_revision(changes):
    assert pol.policy_revision(_with(_index("aios.process.list"), **changes)) == BASE


def test_revision_ignores_entry_order():
    entries = list(default_catalog().entries())
    assert pol.policy_revision(ToolCatalog(reversed(entries))) == BASE


def test_revision_cache_is_bounded():
    for _ in range(3 * pol._MAX_CACHED_REVISIONS):
        pol.policy_revision(ToolCatalog(default_catalog().entries()))
    assert len(pol._REVISIONS) <= pol._MAX_CACHED_REVISIONS


# ---- evaluate (TOOLPOL-INV1/2/4) -------------------------------------------------------------------------------

TOOLS = ["aios.anchor.create", "aios.backup.create", "aios.process.list", "pentest.nmap", "aios.never.registered",
         "", "AIOS.FS.READ"]


@pytest.mark.parametrize("mode,require_grant,legacy", list(itertools.product(["shadow", "strict"], [False, True],
                                                                             [False, True])))
def test_evaluate_is_or_only(monkeypatch, mode, require_grant, legacy):
    set_mode(monkeypatch, mode)
    for tool in TOOLS:
        for surface in pol.SURFACES:
            v = pol.evaluate(tool, surface=surface, require_grant=require_grant, legacy_irreversible=legacy)
            assert v.requires_grant >= require_grant and v.irreversible >= legacy, (tool, surface)
            assert v.registry_added_grant == (v.requires_grant and not require_grant)
            if mode == "shadow":                       # shadow changes nothing at all
                assert (v.requires_grant, v.irreversible, v.registry_added_grant) == (require_grant, legacy, False)
            assert v.mode == mode and v.failure is None


@pytest.mark.parametrize("odd", [None, 42, b"aios.fs.read", ["x"], {"a": 1}, "x" * 10_000, "\x00", "‮"])
def test_evaluate_never_raises_on_odd_input(monkeypatch, odd):
    set_mode(monkeypatch, "strict")
    v = pol.evaluate(odd, target=odd, surface="dispatch", classification=odd if isinstance(odd, dict) else None)
    assert v.requires_grant is True                    # unregistered => grant required in strict (D4)


def test_c3_marks_a_step_irreversible_in_strict(monkeypatch):
    set_mode(monkeypatch, "strict")
    c3 = {"c_flags": {"c3": True}}
    assert pol.evaluate("aios.process.list", surface="agent_loop", classification=c3).irreversible is True


@pytest.mark.parametrize("mode", ["shadow", "strict"])
def test_failure_rule(monkeypatch, mode):
    set_mode(monkeypatch, mode)
    monkeypatch.setattr(trs, "service", lambda: (_ for _ in ()).throw(OSError("x")))
    v = pol.evaluate("aios.process.list", surface="agent_loop")
    assert v.failure == "OSError" and v.irreversible is (mode == "strict") and v.requires_grant is (mode == "strict")


def test_unreadable_mode_fails_closed(monkeypatch):
    def broken():
        raise RuntimeError("config")
    monkeypatch.setattr(trs, "service", broken)
    monkeypatch.setattr(trs, "intended_mode", broken)
    v = pol.evaluate("aios.process.list", surface="dispatch")
    assert v.requires_grant and v.mode == "strict"


def test_failure_is_announced_once_per_surface(monkeypatch, capsys):
    set_mode(monkeypatch, "shadow")
    monkeypatch.setattr(trs, "service", lambda: (_ for _ in ()).throw(KeyError("x")))
    for _ in range(50):
        for surface in pol.SURFACES:
            pol.evaluate("t", surface=surface)
    err = capsys.readouterr().err
    assert err.count("unavailable in dispatch (KeyError); legacy rules only") == 1
    assert err.count("unavailable in the agent loop (KeyError); legacy rules only") == 1
    assert capsys.readouterr().out == ""               # never stdout (the MCP channel)


@pytest.mark.parametrize("surface", ["", "DISPATCH", "cli", None])
def test_unknown_surface_raises(surface):
    with pytest.raises(ValueError):
        pol.evaluate("aios.fs.read", surface=surface)


# ---- grant_reason_suffix (TOOLPOL-INV3) ------------------------------------------------------------------------

@pytest.mark.parametrize("added,failure,revision,expected", [
    (False, None, "trp-1", ""),
    (False, "OSError", "trp-1", ""),
    (True, None, "trp-1", " (tool registry strict, catalog trp-1)"),
    (True, None, "", " (tool registry strict, catalog unknown)"),
    (True, "OSError", "trp-1", " (tool registry unavailable, strict: fail closed)"),
])
def test_suffix_forms(added, failure, revision, expected):
    v = pol.PolicyVerdict(requires_grant=True, irreversible=False, registry_added_grant=added, mode="strict",
                          revision=revision, failure=failure)
    assert pol.grant_reason_suffix(v) == expected


def test_suffix_is_ascii_and_bounded():
    v = pol.PolicyVerdict(True, False, True, "strict", pol.policy_revision())
    s = pol.grant_reason_suffix(v)
    assert s.isascii() and len(s) < 80
