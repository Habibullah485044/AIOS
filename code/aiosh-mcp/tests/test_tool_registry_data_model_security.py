"""Regression tests for the tool registry security review (T-03369).

Each test fails on the pre-T-03369 code (see docs/tasks/evidence/T-03369-security.md).
"""

import pytest

from aiosh_mcp import tool_registry_data_model as reg
from aiosh_mcp.audit_client import network_allowed, path_allowed
from aiosh_mcp.tool_registry_data_model import Category, Effect, ScopeKind, ToolCatalog, ToolEntry, ToolRegistryError

C = reg.default_catalog()


def entry(**kw):
    base = dict(canonical="aios.sec.read", mcp_names=(), title="Sec read", category=Category.FS_READ,
                effect=Effect.READ_ONLY, irreversible=False, scope_kind=ScopeKind.PATH, open_world=False,
                requires_grant=False)
    return ToolEntry(**{**base, **kw})


def code_of(fn):
    with pytest.raises(ToolRegistryError) as exc:
        fn()
    return exc.value.code


# #1: the seeded fs.read entry claimed no grant was needed; the real tool requires one.
def test_fs_read_requires_a_grant_like_the_real_tool():
    assert C.resolve("aios_fs_read").requires_grant is True


# #2: offline pentest tools target a capture *file*; picking the network checker would allow any path.
@pytest.mark.parametrize("name", ["pentest.tshark", "pentest.aircrack-ng"])
def test_offline_pentest_tools_are_path_scoped(name):
    e = C.get(name)
    assert (e.scope_kind, e.open_world, e.irreversible, e.requires_grant) == (ScopeKind.PATH, False, True, True)
    # why it matters: a caller choosing its checker from scope_kind must not end up here
    assert network_allowed("/etc/shadow", []) is True and path_allowed("/etc/shadow", {"allow": ["/tmp"]}) is False


# #3: entries may be stricter than the existing name rules, never weaker.
@pytest.mark.parametrize("kw", [
    dict(canonical="fs.write_all"),                                                       # read-only, no grant
    dict(canonical="system.reboot", category=Category.ADMIN, effect=Effect.ADDITIVE),     # dodges the category rule
    dict(canonical="shell.exec", category=Category.PROCESS, effect=Effect.DESTRUCTIVE),
    dict(canonical="process.kill", category=Category.PROCESS, effect=Effect.DESTRUCTIVE),
    dict(canonical="pentest.nmap2", category=Category.NETWORK, effect=Effect.READ_ONLY, scope_kind=ScopeKind.NETWORK,
         open_world=True),
])
def test_entries_cannot_be_weaker_than_name_rules(kw):
    assert code_of(lambda: entry(**kw)) == "TOOLREG_ERR_INCONSISTENT"


def test_network_category_requires_network_scope():
    assert code_of(lambda: entry(canonical="network.fetch", category=Category.NETWORK, effect=Effect.READ_ONLY,
                                 scope_kind=ScopeKind.NONE)) == "TOOLREG_ERR_INCONSISTENT"


# #4: scope inference for unknown names matches the agent-loop gate (case-insensitive, bare family names).
@pytest.mark.parametrize("name", ["PENTEST.nmap", "pentest", "network", "Network.fetch"])
def test_unknown_scope_inference_is_case_insensitive(name):
    assert C.profile(name).scope_kind is ScopeKind.NETWORK


# #5: malformed names no longer share one synthetic canonical name.
def test_malformed_names_get_distinct_synthetic_names():
    names = ["SYSTEM.reboot", "x" * 65, "a b", "‮pentest"]
    canon = [C.profile(n).canonical for n in names]
    assert len(set(canon)) == len(names) and all(c.startswith(reg.UNREGISTERED_PREFIX) for c in canon)
    assert C.profile("unregistered").canonical == "unregistered"           # a well-formed name keeps its own name
    reserved = entry(canonical="unregistered.0123456789abcdef")
    assert code_of(lambda: ToolCatalog([reserved])) == "TOOLREG_ERR_INVALID_NAME"   # synthetic names not registrable


# #6: separator variants are one name.
def test_separator_variants_collide_across_entries():
    a = entry(canonical="aios.sec.read_x")
    b = entry(canonical="aios.sec.read-x")
    assert code_of(lambda: ToolCatalog([a, b])) == "TOOLREG_ERR_DUPLICATE"
    assert len(ToolCatalog([entry(canonical="aios.sec.read", mcp_names=("aios_sec_read",))])) == 1   # own alias ok


# #8: a str subclass cannot steer a lookup through custom __eq__/__hash__.
def test_str_subclass_cannot_resolve_to_another_entry():
    class Sneaky(str):
        def __hash__(self):
            return hash("aios.fs.read")

        def __eq__(self, other):
            return True

    s = Sneaky("system.reboot")
    assert C.resolve(s) is None and C.get(s) is None
    p = C.profile(s)
    assert p.irreversible and p.requires_grant
