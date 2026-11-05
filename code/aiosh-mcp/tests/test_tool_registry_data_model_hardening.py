"""Hardening tests for the tool registry data model (T-03370).

A broken catalog degrades two tools instead of the whole server; output and lookup cost stay bounded.
"""

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from aiosh_mcp import tool_registry_data_model as reg
from aiosh_mcp.tool_registry_data_model import Category, Effect, ScopeKind, ToolCatalog, ToolEntry, ToolRegistryError

PKG_ROOT = Path(__file__).resolve().parents[1]

BROKEN_CATALOG_PROBE = r"""
import json
from aiosh_mcp import tool_registry_data_model as reg
reg._SEED = reg._SEED + (reg._SEED[0],)           # what a bad merge of the seed would produce
reg.default_catalog.cache_clear()
import aiosh_mcp.server as srv
tools = {t.name: t for t in srv.mcp._tool_manager.list_tools()}
print(json.dumps({"count": len(tools), "list": tools["aios_tool_registry_list"].fn(),
                  "get": tools["aios_tool_registry_get"].fn(name="pentest.newthing"),
                  "other_tool_served": "aios_agent_loop_start" in tools}))
"""


def test_broken_catalog_degrades_two_tools_not_the_server(tmp_path):
    out = subprocess.run([sys.executable, "-c", BROKEN_CATALOG_PROBE], cwd=PKG_ROOT, capture_output=True, text=True,
                         timeout=120, env={**__import__("os").environ, "AIOSH_HOME": str(tmp_path)})
    assert out.returncode == 0, out.stderr[-1500:]
    data = json.loads(out.stdout.strip().splitlines()[-1])
    assert data["other_tool_served"] is True and data["count"] >= 69
    assert data["list"]["ok"] is False and data["list"]["error_code"] == "TOOLREG_ERR_UNAVAILABLE"
    get = data["get"]
    assert get["ok"] is False and get["error_code"] == "TOOLREG_ERR_UNAVAILABLE"
    assert get["data"]["registered"] is False and get["data"]["entry"]["irreversible"] is True   # still fail closed
    assert "TOOLREG_ERR_UNAVAILABLE" in out.stderr                                               # reported


def test_same_entry_listed_twice_is_rejected():
    e = reg.default_catalog().get("aios.fs.read")
    with pytest.raises(ToolRegistryError) as exc:
        ToolCatalog([e, e])
    assert exc.value.code == "TOOLREG_ERR_DUPLICATE"


def _max_entry(i):
    return ToolEntry(canonical=f"aios.h{i:03d}." + "x" * 54, mcp_names=tuple(f"m{i:03d}_{j}_" + "y" * 57 for j in range(8)),
                     title="t" * 64, category=Category.SERVICE, effect=Effect.ADDITIVE, irreversible=False,
                     scope_kind=ScopeKind.NONE, open_world=False, requires_grant=True)


def test_largest_possible_catalog_stays_bounded():
    big = ToolCatalog(_max_entry(i) for i in range(reg.MAX_CATALOG_ENTRIES))
    size = len(big.export_json().encode())
    assert size < 1024 * 1024                                       # well under MCP's 10 MiB payload bound
    started = time.perf_counter()
    for i in range(20_000):
        big.profile(f"aios.h{i % 600:03d}." + "x" * 54)
    assert time.perf_counter() - started < 2.0                       # O(1) lookups, misses included


def test_registry_holds_no_resources():
    """Nothing to clean up: the module opens no files, DBs or processes (checked on its source)."""
    src = Path(reg.__file__).read_text(encoding="utf-8")
    for forbidden in ("open(", "sqlite3", "subprocess", "socket", "Thread("):
        assert forbidden not in src, forbidden
