"""Integration test for the tool registry configuration (T-03408): a real server started with a config file."""

import json
import os
import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from aiosh_mcp import tool_registry_config as cfg

PKG_ROOT = Path(__file__).resolve().parents[1]


async def server_stats(tmp_path, config_doc, extra_env=None):
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(config_doc), encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith("AIOSH_TOOL_REGISTRY_")}
    env.update({"AIOSH_HOME": str(tmp_path), cfg.ENV_CONFIG: str(path), **(extra_env or {})})
    params = StdioServerParameters(command=sys.executable, args=["-m", "aiosh_mcp.server"], cwd=str(PKG_ROOT), env=env)
    async with stdio_client(params) as (r, w), ClientSession(r, w) as session:
        await session.initialize()
        res = await session.call_tool("aios_tool_registry_stats", {})
        return json.loads(res.content[0].text)["data"]


@pytest.mark.anyio
async def test_server_applies_a_config_file(tmp_path):
    data = await server_stats(tmp_path, {"mode": "strict", "report_max_lines": 3, "unregistered_samples": 7})
    assert data["config"]["values"] == {"mode": "strict", "report_max_lines": 3, "unregistered_samples": 7}
    assert data["config"]["sources"] == {"mode": "file", "report_max_lines": "file", "unregistered_samples": "file"}
    assert data["service"]["mode"] == "strict" and data["config_errors"] == []


@pytest.mark.anyio
async def test_env_strict_beats_a_file_shadow(tmp_path):
    data = await server_stats(tmp_path, {"mode": "shadow"}, {cfg.ENV_MODE: "strict"})
    assert data["service"]["mode"] == "strict" and data["config"]["sources"]["mode"] == "env"


@pytest.mark.anyio
async def test_a_bad_file_is_reported_and_the_server_still_serves(tmp_path):
    data = await server_stats(tmp_path, {"catalog": [], "mode": "strict"})
    assert data["service"]["mode"] == "shadow"                       # the whole file was ignored
    assert any(e.startswith("TOOLREGCONF_ERR_LOCKED") for e in data["config_errors"])
