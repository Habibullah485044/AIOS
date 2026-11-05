"""Unit tests for the tool registry data model (T-03367; spec T-03364).

Boundaries, the primary failure modes (aliasing, fail-open lookups, mutation) and permanent drift
checks against the name-based rules the catalog will replace (research T-03363 B3/B4).
"""

import json
import random
import string

import pytest

from aiosh_mcp import tool_registry_data_model as reg
from aiosh_mcp.agent_loop_policy import is_irreversible
from aiosh_mcp.tool_registry_data_model import Category, Effect, ScopeKind, ToolCatalog, ToolEntry, ToolRegistryError

C = reg.default_catalog()


def entry(**kw):
    base = dict(canonical="aios.unit.read", mcp_names=(), title="Unit read", category=Category.FS_READ,
                effect=Effect.READ_ONLY, irreversible=False, scope_kind=ScopeKind.PATH, open_world=False,
                requires_grant=False)
    return ToolEntry(**{**base, **kw})


def code_of(fn):
    with pytest.raises(ToolRegistryError) as exc:
        fn()
    return exc.value.code


# --- boundaries ----------------------------------------------------------------------------------------------

def test_name_length_boundary():
    ok = "a" + "b" * 63
    assert entry(canonical=ok, mcp_names=("M" * 64,)).canonical == ok           # exactly 64 accepted
    assert code_of(lambda: entry(canonical=ok + "c")) == "TOOLREG_ERR_INVALID_NAME"
    assert code_of(lambda: entry(mcp_names=("M" * 65,))) == "TOOLREG_ERR_INVALID_NAME"
    assert code_of(lambda: entry(canonical="")) == "TOOLREG_ERR_INVALID_NAME"
    assert code_of(lambda: entry(mcp_names=("",))) == "TOOLREG_ERR_INVALID_NAME"


def test_alias_count_and_title_boundaries():
    assert len(entry(mcp_names=tuple(f"n{i}" for i in range(8))).mcp_names) == 8
    assert code_of(lambda: entry(mcp_names=tuple(f"n{i}" for i in range(9)))) == "TOOLREG_ERR_BOUNDS"
    assert entry(title="t" * 64).title == "t" * 64
    assert code_of(lambda: entry(title="t" * 65)) == "TOOLREG_ERR_BOUNDS"


@pytest.mark.parametrize("bad", ["aios.fs.read\n", "aios fs", "aios/fs", "1aios.fs", ".aios", "aios.", "aios.fs.read​",
                                 "aios.ﬁle"])
def test_canonical_rejects_whitespace_separators_and_unicode(bad):
    assert code_of(lambda: entry(canonical=bad)) == "TOOLREG_ERR_INVALID_NAME"


def test_catalog_size_boundary(monkeypatch):
    monkeypatch.setattr(reg, "MAX_CATALOG_ENTRIES", 3)
    make = lambda n: [entry(canonical=f"aios.unit.r{i}") for i in range(n)]          # noqa: E731
    assert len(ToolCatalog(make(3))) == 3
    assert code_of(lambda: ToolCatalog(make(4))) == "TOOLREG_ERR_BOUNDS"


# --- primary failure modes -------------------------------------------------------------------------------------

@pytest.mark.parametrize("alias", ["AIOS.UNIT.READ", "aios.unit.reaD", "Aios.Unit.Read"])
def test_case_variants_cannot_alias(alias):
    a = entry()
    assert code_of(lambda: ToolCatalog([a, entry(canonical="aios.unit.other", mcp_names=(alias,))])) \
        == "TOOLREG_ERR_DUPLICATE"


def test_fullwidth_lookalikes_are_not_valid_names():
    assert code_of(lambda: entry(mcp_names=("ａｉｏｓ.unit.read",))) == "TOOLREG_ERR_INVALID_NAME"


def test_duplicate_alias_within_one_entry_rejected():
    assert code_of(lambda: ToolCatalog([entry(mcp_names=("x_tool", "X_TOOL"))])) == "TOOLREG_ERR_DUPLICATE"


def test_lookups_never_fail_open_on_odd_input():
    for odd in (None, 5, b"aios.fs.read", "", " aios.fs.read", "aios.fs.read ", "AIOS.FS.READ", "a" * 10_000):
        assert C.resolve(odd) is None
        p = C.profile(odd)
        assert p.irreversible and p.requires_grant and p.effect is Effect.DESTRUCTIVE
    assert C.get("aios_fs_read") is None                       # get() is canonical-only; MCP aliases need resolve()


def test_unknown_profile_does_not_echo_hostile_names():
    hostile = "pentest.x\x1b[31m‮evil" + "A" * 10_000
    assert C.profile(hostile).canonical == "unregistered"
    with pytest.raises(ToolRegistryError) as exc:
        C.require(hostile)
    msg = str(exc.value)
    # neither the raw characters nor their escaped repr forms, and bounded length
    assert not any(s in msg for s in ("\x1b", "‮", "x1b", "202e")) and len(msg) < 200


def test_profile_scope_follows_network_prefix():
    assert C.profile("pentest.newtool").scope_kind is ScopeKind.NETWORK
    assert C.profile("network.scan").scope_kind is ScopeKind.NETWORK
    assert C.profile("pentesting.x").scope_kind is ScopeKind.PATH            # no dot boundary, no network


def test_catalog_and_entries_cannot_be_mutated():
    e = C.get("fs.write")
    for attr, value in (("irreversible", False), ("requires_grant", False), ("mcp_names", ("x",))):
        with pytest.raises(Exception):
            setattr(e, attr, value)
    with pytest.raises(AttributeError):
        C._entries = ()
    with pytest.raises(TypeError):
        C.names()["evil.tool"] = e                             # read-only mapping
    assert C.get("fs.write").irreversible is True


def test_random_names_never_crash_or_register():
    rng = random.Random(3367)
    alphabet = string.ascii_letters + string.digits + "._-/ \x00‮é"
    for _ in range(2000):
        name = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 80)))
        p = C.profile(name)
        assert C.resolve(name) is not None or (p.irreversible and C.get(p.canonical) is None)


# --- export ----------------------------------------------------------------------------------------------------

def test_export_round_trips_into_an_equal_catalog():
    data = json.loads(C.export_json())
    rebuilt = ToolCatalog(ToolEntry(canonical=d["canonical"], mcp_names=tuple(d["mcp_names"]), title=d["title"],
                                    category=Category(d["category"]), effect=Effect(d["effect"]),
                                    irreversible=d["irreversible"], scope_kind=ScopeKind(d["scope_kind"]),
                                    open_world=d["open_world"], requires_grant=d["requires_grant"],
                                    idempotent=d["idempotent"]) for d in data["entries"])
    assert rebuilt.export_json() == C.export_json()
    assert C.export_json().isascii()


# --- permanent drift checks against the existing name rules (spec §5) ---------------------------------------------

def _grant_check_irreversible(tool):            # audit_client.grant_check, lines 436-440
    return tool.startswith("pentest.") or tool.startswith("fs.write") or tool in ("system.reboot", "system.shutdown")


@pytest.mark.parametrize("e", C.entries(), ids=lambda e: e.canonical)
def test_catalog_agrees_with_existing_irreversible_rules(e):
    assert e.irreversible == _grant_check_irreversible(e.canonical), "grant_check disagrees"
    assert e.irreversible == is_irreversible(e.canonical, {}), "agent_loop_policy disagrees"


@pytest.mark.parametrize("e", C.entries(), ids=lambda e: e.canonical)
def test_catalog_agrees_with_network_rule(e):
    assert (e.scope_kind is ScopeKind.NETWORK) == e.canonical.startswith(reg.NETWORK_PREFIXES)


def test_every_entry_is_consistent_and_annotatable():
    for e in C.entries():
        a = C.annotations(e.canonical)
        assert a.readOnlyHint == (e.effect is Effect.READ_ONLY)
        assert a.openWorldHint == e.open_world
        if e.irreversible:
            assert a.readOnlyHint is False and e.requires_grant
