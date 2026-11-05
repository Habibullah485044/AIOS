"""Implementation tests for the tool registry data model (T-03366; spec T-03364)."""

import json

import pytest

from aiosh_mcp import tool_registry_data_model as reg
from aiosh_mcp.agent_bridge import CANONICAL_TO_MCP
from aiosh_mcp.agent_loop_mcp import TOOL_ANNOTATIONS
from aiosh_mcp.tool_registry_data_model import Category, Effect, ScopeKind, ToolCatalog, ToolEntry, ToolRegistryError

C = reg.default_catalog()


def entry(**kw):
    base = dict(canonical="aios.demo.read", mcp_names=("aios_demo_read",), title="Demo read", category=Category.FS_READ,
                effect=Effect.READ_ONLY, irreversible=False, scope_kind=ScopeKind.PATH, open_world=False,
                requires_grant=False)
    return ToolEntry(**{**base, **kw})


def code_of(fn):
    with pytest.raises(ToolRegistryError) as exc:
        fn()
    return exc.value.code


def test_valid_entry_and_dict_round_trip():
    e = entry()
    d = e.to_dict()
    assert d["category"] == "fs.read" and d["mcp_names"] == ["aios_demo_read"] and json.dumps(d)


@pytest.mark.parametrize("kw,code", [
    ({"canonical": "Aios.Demo"}, "TOOLREG_ERR_INVALID_NAME"),            # canonical is lower-case
    ({"canonical": "aios..demo"}, "TOOLREG_ERR_INVALID_NAME"),
    ({"canonical": "a" * 65}, "TOOLREG_ERR_INVALID_NAME"),
    ({"mcp_names": ("bad name",)}, "TOOLREG_ERR_INVALID_NAME"),
    ({"mcp_names": tuple(f"n{i}" for i in range(9))}, "TOOLREG_ERR_BOUNDS"),
    ({"title": ""}, "TOOLREG_ERR_BOUNDS"),
    ({"title": "x‮y"}, "TOOLREG_ERR_INVALID_NAME"),                # bidi override (MCPDM-INV3)
    ({"category": "fs.read"}, "TOOLREG_ERR_INCONSISTENT"),               # must be the enum, not a string
    ({"irreversible": True}, "TOOLREG_ERR_INCONSISTENT"),               # read_only cannot be irreversible
    ({"idempotent": True}, "TOOLREG_ERR_INCONSISTENT"),                 # meaningless for read_only
    ({"effect": Effect.DESTRUCTIVE, "irreversible": True}, "TOOLREG_ERR_INCONSISTENT"),   # irreversible needs a grant
    ({"scope_kind": ScopeKind.NETWORK}, "TOOLREG_ERR_INCONSISTENT"),    # network ⇒ open world
    ({"category": Category.PENTEST, "effect": Effect.ADDITIVE, "requires_grant": True, "irreversible": True,
      "scope_kind": ScopeKind.NONE}, "TOOLREG_ERR_INCONSISTENT"),        # pentest ⇒ path or network scope (T-03369)
    ({"category": Category.FS_WRITE, "effect": Effect.DESTRUCTIVE}, "TOOLREG_ERR_INCONSISTENT"),   # fs.write ⇒ irreversible
    ({"irreversible": 1}, "TOOLREG_ERR_INCONSISTENT"),                  # bools are bools
])
def test_invalid_entries_rejected(kw, code):
    assert code_of(lambda: entry(**kw)) == code


def test_catalog_uniqueness_is_case_insensitive():
    a = entry()
    assert code_of(lambda: ToolCatalog([a, entry(mcp_names=())])) == "TOOLREG_ERR_DUPLICATE"           # canonical
    assert code_of(lambda: ToolCatalog([a, entry(canonical="aios.other", mcp_names=("AIOS_DEMO_READ",))])) \
        == "TOOLREG_ERR_DUPLICATE"                                                                        # alias case
    assert code_of(lambda: ToolCatalog([a, entry(canonical="aios.other", mcp_names=("aios.demo.read",))])) \
        == "TOOLREG_ERR_DUPLICATE"                                                                        # alias = canonical


def test_catalog_bound(monkeypatch):
    monkeypatch.setattr(reg, "MAX_CATALOG_ENTRIES", 2)
    entries = [entry(canonical=f"aios.demo.r{i}", mcp_names=()) for i in range(3)]
    assert code_of(lambda: ToolCatalog(entries)) == "TOOLREG_ERR_BOUNDS"


def test_lookups():
    nmap = C.get("pentest.nmap")
    assert (nmap.category, nmap.irreversible, nmap.scope_kind) == (Category.PENTEST, True, ScopeKind.NETWORK)
    assert C.resolve("aios_pentest_nmap") is nmap and C.resolve("pentest.nmap") is nmap
    assert C.resolve("AIOS_PENTEST_NMAP") is None                      # resolve is exact
    assert C.require("aios_fs_read").canonical == "aios.fs.read"
    assert code_of(lambda: C.require("nope.tool")) == "TOOLREG_ERR_UNKNOWN"
    assert [e.canonical for e in C.entries()] == sorted(e.canonical for e in C.entries())


@pytest.mark.parametrize("name,scope", [("pentest.zap", ScopeKind.NETWORK), ("network.probe", ScopeKind.NETWORK),
                                        ("aios.fs.write", ScopeKind.PATH), ("bad name\x00", ScopeKind.PATH)])
def test_unknown_tools_fail_closed(name, scope):
    p = C.profile(name)
    assert (p.irreversible, p.requires_grant, p.effect, p.open_world, p.scope_kind) == \
        (True, True, Effect.DESTRUCTIVE, True, scope)
    assert C.get(p.canonical) is None                                  # never registered
    if not reg.CANONICAL_RE.fullmatch(name):
        assert p.canonical.startswith(reg.UNREGISTERED_PREFIX)         # malformed names are not echoed (T-03369 #5)


def test_annotations_are_derived():
    ro = C.annotations("aios_fs_read")
    assert (ro.readOnlyHint, ro.destructiveHint, ro.idempotentHint, ro.openWorldHint) == (True, None, None, False)
    nmap = C.annotations("pentest.nmap")
    assert nmap.readOnlyHint is False and nmap.openWorldHint is True
    assert code_of(lambda: C.annotations("nope.tool")) == "TOOLREG_ERR_UNKNOWN"


def test_agent_loop_entries_agree_with_published_annotations():
    for mcp_name in ("aios_agent_loop_start", "aios_agent_loop_advance", "aios_agent_loop_abort",
                     "aios_agent_loop_complete", "aios_agent_loop_recover"):
        ours, theirs = C.annotations(mcp_name), TOOL_ANNOTATIONS[mcp_name]
        assert (ours.readOnlyHint, ours.destructiveHint, ours.idempotentHint, ours.openWorldHint) == \
            (theirs.readOnlyHint, theirs.destructiveHint, theirs.idempotentHint, theirs.openWorldHint), mcp_name


def test_default_catalog_covers_spec_seed():
    for canonical, mcp_name in CANONICAL_TO_MCP.items():
        assert C.resolve(mcp_name) is C.get(canonical) is not None
    for name in ("aios.agent_loop.start", "aios.agent_loop.step", "aios.agent_loop.abort", "aios.agent_loop.complete",
                 "aios.agent_loop.recover", "audit.rotate", "fs.write", "system.reboot", "system.shutdown"):
        assert C.get(name) is not None, name


def test_export_is_deterministic_json():
    a, b = C.export_json(), reg.default_catalog().export_json()
    data = json.loads(a)
    assert a == b and data["schema_version"] == 1
    assert [e["canonical"] for e in data["entries"]] == sorted(e["canonical"] for e in data["entries"])


def test_catalog_is_immutable():
    with pytest.raises(Exception):
        C.get("pentest.nmap").irreversible = False                      # frozen entry
    assert not hasattr(C, "register") and not hasattr(C, "add") and not hasattr(C, "remove")
    assert isinstance(C.entries(), tuple)
