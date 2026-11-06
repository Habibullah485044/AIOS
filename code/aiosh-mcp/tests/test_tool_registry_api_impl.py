"""Implementation tests for the tool registry API surface (T-03396; spec T-03394)."""

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from aiosh_mcp import tool_registry_api as api
from aiosh_mcp import tool_registry_service as trs
from aiosh_mcp.server import mcp as server_app
from aiosh_mcp.tool_registry_data_model import Effect, default_catalog

C = default_catalog()
TOOLS = {t.name: t for t in server_app._tool_manager.list_tools()}


def caution(a):
    """(readOnly, destructive, idempotent, openWorld) with MCP defaults for omitted hints."""
    if a is None:
        return (False, True, False, True)
    ro = bool(a.readOnlyHint)
    return (ro, None if ro else (True if a.destructiveHint is None else a.destructiveHint),
            None if ro else bool(a.idempotentHint), True if a.openWorldHint is None else a.openWorldHint)


def test_new_tools_are_served_read_only():
    for name in (api.DECIDE_TOOL, api.STATS_TOOL):
        assert name in TOOLS and TOOLS[name].annotations.readOnlyHint is True
        assert C.resolve(name) is not None and C.resolve(name).effect is Effect.READ_ONLY


def test_decide_tool_does_not_touch_server_telemetry():
    before = trs.service().stats()["decisions"]
    d = TOOLS[api.DECIDE_TOOL].fn(name="pentest.tshark")["data"]
    assert d["canonical"] == "pentest.tshark" and d["scope_kinds"] == ["network", "path"] and d["target_checked"] is False
    assert trs.service().stats()["decisions"] == before          # T-03399 F3: decide has its own counters


def test_stats_tool_shape():
    s = TOOLS[api.STATS_TOOL].fn()["data"]
    assert set(s) == {"service", "reports", "config", "config_errors"} and s["service"]["catalog_entries"] == len(C)
    assert set(s["reports"]) == {"lines", "suppressed"}


def test_every_served_tool_now_has_annotations():
    assert all(t.annotations is not None for t in TOOLS.values())


def test_read_only_hint_only_under_the_conjunction():
    for name, t in TOOLS.items():
        e = C.resolve(name)
        if t.annotations.readOnlyHint:
            assert e.effect is Effect.READ_ONLY and not e.requires_grant, name
            assert e.category.value in api.READ_ONLY_HINT_CATEGORIES, name


def test_consequential_tools_still_look_consequential():
    for name in ("aios_pentest_nmap", "aios_backup_create", "aios_agent_loop_abort", "aios.release.generate"):
        ro, destructive, _, _ = caution(TOOLS[name].annotations)
        assert ro is False, name
    assert caution(TOOLS["aios_pentest_nmap"].annotations)[3] is True        # open world


@pytest.mark.parametrize("existing", [None, ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True),
                                      ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True,
                                                      openWorldHint=False)])
@pytest.mark.parametrize("derived", [ToolAnnotations(readOnlyHint=True, openWorldHint=False),
                                     ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True,
                                                     openWorldHint=False)])
@pytest.mark.parametrize("allow", [True, False])
def test_merge_never_relaxes(existing, derived, allow):
    merged = api.more_cautious(existing, derived, allow)
    old, new = caution(existing), caution(merged)
    if not old[0]:
        assert new[0] is False or (allow and existing is None)               # readOnly only gained where allowed
    if not new[0] and not old[0]:
        assert (new[1] or not old[1]) and (new[3] or not old[3])           # destructive / open world never dropped
        assert not new[2] or old[2]                                       # never newly claims idempotent


def test_equivalent_existing_annotations_are_kept_as_is():
    existing = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
    assert api.more_cautious(existing, ToolAnnotations(readOnlyHint=True, openWorldHint=False), True) is existing


def test_apply_on_a_fresh_server_reports_counts():
    app = FastMCP("t")

    @app.tool(name="aios_audit_tail")
    def tail() -> dict:
        return {}

    @app.tool(name="not_in_catalog")
    def other() -> dict:
        return {}

    counts = api.apply_catalog_annotations(app)
    assert counts == {"applied": 1, "unchanged": 0, "skipped_unregistered": 1, "errors": 0}
    tools = {t.name: t for t in app._tool_manager.list_tools()}
    assert tools["aios_audit_tail"].annotations.readOnlyHint is True and tools["not_in_catalog"].annotations is None


def test_broken_catalog_changes_nothing(monkeypatch):
    def broken():
        from aiosh_mcp.tool_registry_data_model import ToolRegistryError
        raise ToolRegistryError("TOOLREG_ERR_DUPLICATE", "bad")
    monkeypatch.setattr(api, "default_catalog", broken)
    app = FastMCP("t")

    @app.tool(name="aios_audit_tail")
    def tail() -> dict:
        return {}

    assert api.apply_catalog_annotations(app) == {"error": "TOOLREG_ERR_UNAVAILABLE"}
    assert app._tool_manager.list_tools()[0].annotations is None
