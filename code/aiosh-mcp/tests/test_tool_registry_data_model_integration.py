"""Integration tests for the tool registry data model (T-03368): real stdio MCP server, TS parity."""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from aiosh_mcp import tool_registry_data_model as reg
from aiosh_mcp.server import mcp as server_app

PKG_ROOT = Path(__file__).resolve().parents[1]
TS_ROOT = PKG_ROOT.parent / "aiosh-cli"
PEP_JS = TS_ROOT / "dist" / "pep.js"
C = reg.default_catalog()


@pytest.mark.anyio
async def test_catalog_tools_over_stdio(tmp_path):
    params = StdioServerParameters(command=sys.executable, args=["-m", "aiosh_mcp.server"], cwd=str(PKG_ROOT),
                                   env=dict(os.environ, AIOSH_HOME=str(tmp_path)))
    async with stdio_client(params) as (r, w), ClientSession(r, w) as session:
        await session.initialize()
        tools = {t.name: t for t in (await session.list_tools()).tools}

        async def call(name, args):
            res = await session.call_tool(name, args)
            return res.isError, (json.loads(res.content[0].text) if not res.isError else res.content[0].text)

        listed = await call(reg.LIST_TOOL, {})
        pentest = await call(reg.LIST_TOOL, {"category": "pentest"})
        nmap = await call(reg.GET_TOOL, {"name": "aios_pentest_nmap"})
        unknown = await call(reg.GET_TOOL, {"name": "pentest.newthing"})
        bad_category = await call(reg.LIST_TOOL, {"category": "root"})
        too_long = await call(reg.GET_TOOL, {"name": "x" * 300})
    for name in (reg.LIST_TOOL, reg.GET_TOOL):
        ann = tools[name].annotations
        assert ann.readOnlyHint is True and ann.openWorldHint is False          # derived from its own entry
    assert listed[1]["data"]["count"] == len(C) and listed[1]["data"]["entries"] == C.to_dict()["entries"]
    assert {e["category"] for e in pentest[1]["data"]["entries"]} == {"pentest"}
    assert nmap[1]["data"]["registered"] is True and nmap[1]["data"]["entry"]["canonical"] == "pentest.nmap"
    assert unknown[1]["data"]["registered"] is False
    assert unknown[1]["data"]["entry"]["irreversible"] is True and unknown[1]["data"]["entry"]["scope_kind"] == "network"
    assert bad_category[0] is True and too_long[0] is True                   # schema-validated, not served


def test_served_tools_without_catalog_entries_are_tracked():
    """Spec §3: served MCP tools with no entry are listed (tracked, not failed) until coverage is complete."""
    served = {t.name for t in server_app._tool_manager.list_tools()}
    missing = sorted(n for n in served if C.resolve(n) is None)
    covered = len(served) - len(missing)
    # Every catalog MCP alias that claims to be served really is (no stale aliases for agent-loop / registry tools).
    for e in C.entries():
        for alias in e.mcp_names:
            if alias.startswith(("aios_agent_loop_", "aios_tool_registry_", "aios_fs_", "aios_process_",
                                 "aios_audit_", "aios_pentest_")):
                assert alias in served, alias
    assert covered >= 17 and len(missing) < len(served)
    print(f"catalog covers {covered}/{len(served)} served tools; untracked: {len(missing)}")


def _ts_tool_classes():
    text = (TS_ROOT / "src" / "types.ts").read_text(encoding="utf-8")
    m = re.search(r"export type ToolClass\s*=([^;]+);", text)
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def test_categories_cover_the_ts_tool_class_union():
    assert _ts_tool_classes() <= {c.value for c in reg.Category}


@pytest.mark.skipif(shutil.which("node") is None or not PEP_JS.exists(), reason="node or aiosh-cli dist missing")
def test_ts_pep_agrees_on_irreversibility(tmp_path):
    names = [e.canonical for e in C.entries()]
    probe = tmp_path / "probe.mjs"
    probe.write_text(f"import {{ isIrreversible }} from {json.dumps(PEP_JS.as_uri())};\n"
                     f"console.log(JSON.stringify({json.dumps(names)}.map((n) => isIrreversible(n))));\n",
                     encoding="utf-8")
    out = subprocess.run(["node", str(probe)], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-1000:]
    ts = dict(zip(names, json.loads(out.stdout.strip().splitlines()[-1])))
    disagree = {n: (C.get(n).irreversible, ts[n]) for n in names if C.get(n).irreversible != ts[n]}
    assert disagree == {}, f"catalog vs TS isIrreversible: {disagree}"
