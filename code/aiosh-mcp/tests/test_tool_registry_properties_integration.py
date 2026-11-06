"""Property P3 across the production surfaces (T-03418): the MCP tool, the CLI and the service agree.

The generated names of the property suite are sent through `aios_tool_registry_decide` (as registered on the real
server) and `aiosh-tool-registry decide` (CLI core); both must equal the service's own decision and stay above the
never-weaker floor.
"""

import random

import pytest

import tool_registry_model as M
from aiosh_mcp import tool_registry_api as api
from aiosh_mcp import tool_registry_cli as cli
from aiosh_mcp.server import mcp as server_app
from aiosh_mcp.tool_registry_data_model import MAX_QUERY_LEN, default_catalog
from aiosh_mcp.tool_registry_service import ToolRegistryService

DECIDE = {t.name: t for t in server_app._tool_manager.list_tools()}[api.DECIDE_TOOL]
FIELDS = ("canonical", "registered", "requires_grant", "irreversible", "scope_kinds", "disagreements")


@pytest.mark.parametrize("seed", M.seeds())
def test_mcp_cli_and_service_agree(seed, monkeypatch):
    monkeypatch.delenv("AIOSH_TOOL_REGISTRY_MODE", raising=False)
    rng = random.Random(seed)
    catalog = default_catalog()
    svc = ToolRegistryService(catalog, mode="shadow")
    registered = list(catalog.names())
    checked = 0
    for case in range(min(M.n_cases(), 150)):
        name = M.gen_query_name(rng, registered)
        if type(name) is not str or not (1 <= len(name) <= MAX_QUERY_LEN) or "\x00" in name:
            continue                                   # rejected by the published schema / CLI usage rules
        d = svc.decide(name)
        expected = {"canonical": d.canonical, "registered": d.registered, "requires_grant": d.requires_grant,
                    "irreversible": d.irreversible, "scope_kinds": [k.value for k in d.scope_kinds],
                    "disagreements": list(d.disagreements)}
        via_mcp = DECIDE.fn(name=name)["data"]
        via_cli = cli.dispatch_cli(["decide", name]).data
        where = f"seed={seed} case={case} name={name!r}"
        assert {k: via_mcp[k] for k in FIELDS} == expected == {k: via_cli[k] for k in FIELDS}, where
        grant, irrev = M.legacy_floor(name)
        assert via_mcp["requires_grant"] >= grant and via_mcp["irreversible"] >= irrev, where
        checked += 1
    assert checked > 50
