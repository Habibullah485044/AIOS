"""Integration tests for the tool registry security policy (T-03428; spec T-03424).

The policy is reachable from its production surfaces (dispatch, the agent loop, the MCP decide/stats tools and the
``aiosh-tool-registry decide`` CLI), and every surface reports the same verdict and catalog revision."""

import json

import pytest

from aiosh_mcp import tool_registry_cli as cli
from aiosh_mcp import tool_registry_config
from aiosh_mcp import tool_registry_policy as pol
from aiosh_mcp import tool_registry_service as trs
from aiosh_mcp.tool_registry_api import DECIDE_TOOL, STATS_TOOL


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("AIOSH_HOME", str(tmp_path))
    monkeypatch.delenv(trs.ENV_MODE, raising=False)
    return tmp_path


def set_mode(monkeypatch, mode):
    if mode == "strict":
        monkeypatch.setenv(trs.ENV_MODE, "strict")
    else:
        monkeypatch.delenv(trs.ENV_MODE, raising=False)
    tool_registry_config.reset_process_config()
    monkeypatch.setattr(trs, "_SERVICE", None)
    pol.reset_process_state()


def mcp_tools():
    from aiosh_mcp.server import mcp
    return {t.name: t for t in mcp._tool_manager.list_tools()}


def cli_decide(*argv):
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = cli.main(["decide", *argv, "--json"])
    assert code == 0
    return json.loads(buf.getvalue())["data"]


GRANT_TOOLS = ["aios.anchor.create", "aios.backup.create", "pentest.nmap", "aios.never.registered"]


@pytest.mark.parametrize("tool", GRANT_TOOLS)
def test_cli_preview_matches_the_real_dispatch_refusal(monkeypatch, tool):
    from aiosh_mcp import _dispatch
    set_mode(monkeypatch, "strict")
    preview = cli_decide(tool, "--mode", "strict")["policy"]
    verdict, _row = _dispatch.dispatch(tool=tool, command="x", args={}, target=None, grant_id=None,
                                       require_grant=False)
    assert preview["enforced_requires_grant"] is True and verdict["ok"] is False and verdict["gate"] == "pep"
    assert verdict["reason"] == f"tool '{tool}' requires explicit PEP grant{preview['grant_reason_suffix']}"


@pytest.mark.parametrize("mode", ["shadow", "strict"])
def test_mcp_decide_reports_the_policy_and_matches_evaluate(monkeypatch, mode):
    set_mode(monkeypatch, mode)
    tools = mcp_tools()
    for tool in GRANT_TOOLS + ["aios.process.list"]:
        data = tools[DECIDE_TOOL].fn(name=tool)["data"]
        v = pol.evaluate(tool, surface="dispatch")
        assert data["policy"] == {"policy_revision": v.revision, "enforced_requires_grant": v.requires_grant,
                                  "enforced_irreversible": v.irreversible,
                                  "registry_added_grant": v.registry_added_grant,
                                  "grant_reason_suffix": pol.grant_reason_suffix(v)}, tool


def test_every_surface_reports_one_revision(monkeypatch):
    set_mode(monkeypatch, "strict")
    tools = mcp_tools()
    revs = {pol.policy_revision(), tools[STATS_TOOL].fn()["data"]["policy_revision"],
            tools[DECIDE_TOOL].fn(name="aios.fs.read")["data"]["policy"]["policy_revision"],
            cli_decide("aios.fs.read", "--mode", "strict")["policy"]["policy_revision"]}
    assert len(revs) == 1 and next(iter(revs)).startswith("trp-")


def test_shadow_preview_enforces_nothing_extra():
    data = cli_decide("aios.anchor.create")
    assert data["requires_grant"] is True                                   # what the catalog says ...
    assert data["policy"]["enforced_requires_grant"] is False               # ... is not enforced in shadow
    assert data["policy"]["grant_reason_suffix"] == ""


def test_caller_grant_is_never_attributed_to_the_registry():
    data = cli_decide("aios.anchor.create", "--mode", "strict", "--require-grant")["policy"]
    assert data["enforced_requires_grant"] is True and data["registry_added_grant"] is False


def test_preview_is_pure(monkeypatch, capsys):
    set_mode(monkeypatch, "strict")
    svc = trs.ToolRegistryService(mode="strict")
    before = (trs.report_stats(), set(pol._LOGGED))
    for _ in range(20):
        pol.preview(svc, svc.decide("aios.anchor.create"))
    assert (trs.report_stats(), set(pol._LOGGED)) == before
    assert capsys.readouterr().err == ""


def test_human_decide_output_shows_the_policy(capsys):
    assert cli.main(["decide", "aios.anchor.create", "--mode", "strict"]) == 0
    out = capsys.readouterr().out
    assert "policy.enforced_requires_grant: True" in out and "policy.policy_revision: trp-" in out
