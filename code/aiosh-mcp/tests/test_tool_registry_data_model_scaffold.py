"""Scaffold tests for the tool registry data model (T-03365; spec T-03364)."""

import dataclasses

import pytest

from aiosh_mcp import tool_registry_data_model as reg
from aiosh_mcp.mcp_server_core_data_model import MAX_TOOL_NAME_LEN


def test_enums_and_constants_match_spec():
    assert {c.value for c in reg.Category} >= {"fs.read", "fs.write", "process", "audit", "pentest", "network",
                                               "gui", "system"}             # the TS ToolClass set
    assert [e.value for e in reg.Effect] == ["read_only", "additive", "destructive"]
    assert [s.value for s in reg.ScopeKind] == ["none", "path", "network"]
    assert reg.MAX_NAME_LEN == MAX_TOOL_NAME_LEN
    codes = [v for k, v in vars(reg).items() if k.startswith("TOOLREG_ERR_")]
    assert sorted(codes) == sorted(["TOOLREG_ERR_INVALID_NAME", "TOOLREG_ERR_INCONSISTENT", "TOOLREG_ERR_DUPLICATE",
                                    "TOOLREG_ERR_BOUNDS", "TOOLREG_ERR_UNKNOWN"])


def test_entry_is_frozen_with_spec_fields():
    fields = [f.name for f in dataclasses.fields(reg.ToolEntry)]
    assert fields == ["canonical", "mcp_names", "title", "category", "effect", "irreversible", "scope_kind",
                      "open_world", "requires_grant", "idempotent"]
    assert reg.ToolEntry.__dataclass_params__.frozen


def test_stubs_fail_loudly():
    for call in (lambda: reg.ToolCatalog([]), reg.default_catalog, lambda: reg.unknown_profile("x")):
        with pytest.raises(NotImplementedError, match="T-03366"):
            call()


def test_error_carries_code():
    err = reg.ToolRegistryError(reg.TOOLREG_ERR_UNKNOWN, "nope")
    assert err.code == "TOOLREG_ERR_UNKNOWN" and str(err).startswith("TOOLREG_ERR_UNKNOWN") and isinstance(err, ValueError)
