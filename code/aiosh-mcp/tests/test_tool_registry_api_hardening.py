"""Hardening tests for the tool registry API surface (T-03400): the import-time annotation pass never fails."""

import pytest
from mcp.server.fastmcp import FastMCP

from aiosh_mcp import tool_registry_api as api


@pytest.mark.parametrize("schema", [[1, 2], "x", 7, {"properties": "path"}, {"properties": 5}])
def test_unreadable_schemas_fail_closed(schema):
    assert api.unsafe_for_read_only_hint(schema) is True             # no read-only hint for what we cannot read


def test_no_properties_is_not_unsafe():
    assert api.unsafe_for_read_only_hint({"type": "object"}) is False
    assert api.unsafe_for_read_only_hint({"properties": None}) is False


def test_one_broken_tool_does_not_stop_the_pass(capsys, monkeypatch):
    app = FastMCP("t")
    app.add_tool(lambda: {}, name="aios_audit_tail")
    app.add_tool(lambda: {}, name="aios_audit_segments")
    broken = app._tool_manager.list_tools()[0]
    monkeypatch.setattr(broken, "parameters", [1, 2])                 # unreadable: no read-only hint, but no crash
    real = api.more_cautious

    def flaky(existing, derived, allow):
        if derived.title == "List audit segments":
            raise RuntimeError("boom")
        return real(existing, derived, allow)
    monkeypatch.setattr(api, "more_cautious", flaky)
    counts = api.apply_catalog_annotations(app)
    assert counts == {"applied": 1, "unchanged": 0, "skipped_unregistered": 0, "errors": 1}
    tools = {t.name: t for t in app._tool_manager.list_tools()}
    assert tools["aios_audit_segments"].annotations is None          # left exactly as it was
    assert tools["aios_audit_tail"].annotations.readOnlyHint is False  # unreadable schema: fail closed
    assert "annotations unchanged" in capsys.readouterr().err
