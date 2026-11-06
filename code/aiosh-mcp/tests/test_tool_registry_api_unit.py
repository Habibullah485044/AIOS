"""Unit tests for the tool registry API surface (T-03397; spec T-03394)."""

import pytest
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from aiosh_mcp import tool_registry_api as api
from aiosh_mcp.server import mcp as server_app

TOOLS = {t.name: t for t in server_app._tool_manager.list_tools()}
DECIDE, STATS = TOOLS[api.DECIDE_TOOL], TOOLS[api.STATS_TOOL]


# --- argument boundaries (schema-validated by FastMCP before the tool runs) ---------------------------------------

@pytest.mark.parametrize("args,ok", [({"name": "x"}, True), ({"name": "x" * 256}, True), ({"name": "x" * 257}, False),
                                     ({"name": ""}, False), ({"name": 5}, False), ({}, False),
                                     ({"name": "x", "require_grant": True}, True)])
def test_decide_argument_schema(args, ok):
    model = DECIDE.fn_metadata.arg_model
    if ok:
        model.model_validate(args)
    else:
        with pytest.raises(Exception):
            model.model_validate(args)


def test_decide_require_grant_and_unknown_names():
    assert DECIDE.fn(name="aios.fs.read", require_grant=True)["data"]["disagreements"] == []
    u = DECIDE.fn(name="aios.unknown.thing")["data"]
    assert u["registered"] is False and u["requires_grant"] is True and "unregistered" in u["disagreements"]


def test_decide_calls_are_not_counted_and_stats_never_hold_names():
    before = STATS.fn()["data"]["service"]
    DECIDE.fn(name="aios.secret_name_x")
    after = STATS.fn()["data"]["service"]
    assert after == before                                       # T-03399 F3/S1: no pollution, no membership oracle
    assert "secret_name_x" not in str(after)


# --- merge edge cases ---------------------------------------------------------------------------------------------

def test_explicit_read_only_is_withdrawn_when_the_catalog_disallows_it():
    existing = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
    merged = api.more_cautious(existing, ToolAnnotations(readOnlyHint=False, destructiveHint=True), allow_read_only=False)
    assert merged.readOnlyHint is False and merged.destructiveHint is True


def test_explicit_false_read_only_is_never_upgraded():
    existing = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)
    merged = api.more_cautious(existing, ToolAnnotations(readOnlyHint=True, openWorldHint=False), allow_read_only=True)
    assert merged.readOnlyHint is False


def test_existing_title_is_kept():
    merged = api.more_cautious(ToolAnnotations(title="Mine", readOnlyHint=False), ToolAnnotations(title="Catalog",
                                                                                                readOnlyHint=True),
                               allow_read_only=False)
    assert merged.title == "Mine"


def test_open_world_is_sticky():
    merged = api.more_cautious(ToolAnnotations(readOnlyHint=False, openWorldHint=True),
                               ToolAnnotations(readOnlyHint=False, openWorldHint=False), allow_read_only=False)
    assert merged.openWorldHint is True


# --- the annotation pass --------------------------------------------------------------------------------------------

def test_apply_is_idempotent():
    app = FastMCP("t")
    for name in ("aios_audit_tail", "aios_pentest_nmap", "aios_agent_loop_snapshot"):
        app.add_tool(lambda: {}, name=name)
    first = api.apply_catalog_annotations(app)
    second = api.apply_catalog_annotations(app)
    assert first["applied"] == 3 and second == {"applied": 0, "unchanged": 3, "skipped_unregistered": 0, "errors": 0}


def test_live_server_pass_is_a_fixed_point():
    snapshot = {n: t.annotations for n, t in TOOLS.items()}
    counts = api.apply_catalog_annotations(server_app)
    assert counts["applied"] == 0                                     # already applied at import
    assert all(TOOLS[n].annotations is a for n, a in snapshot.items())
