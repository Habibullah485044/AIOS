"""Integration tests for the tool registry CLI (T-03388): the real entry points and cross-substrate parity."""

import importlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from aiosh_mcp import audit_client
from aiosh_mcp.server import mcp as server_app
from aiosh_mcp.tool_registry_data_model import default_catalog

PKG_ROOT = Path(__file__).resolve().parents[1]
TS_PEP = PKG_ROOT.parent / "aiosh-cli" / "dist" / "pep.js"
C = default_catalog()


def cli(*args, tmp_path):
    out = subprocess.run([sys.executable, "-m", "aiosh_mcp.tool_registry_cli", *args], cwd=PKG_ROOT,
                         capture_output=True, text=True, timeout=120, env=dict(os.environ, AIOSH_HOME=str(tmp_path)))
    return out.returncode, out.stdout, out.stderr


def test_console_script_entry_point_resolves():
    text = (PKG_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    target = re.search(r'^aiosh-tool-registry = "([\w.]+):(\w+)"', text, re.M)
    assert target, "console script missing from pyproject.toml"
    fn = getattr(importlib.import_module(target.group(1)), target.group(2))
    assert callable(fn) and fn(["list", "--json"]) == 0


def test_python_m_entry_point_end_to_end(tmp_path):
    code, out, err = cli("list", "--json", tmp_path=tmp_path)
    assert code == 0 and json.loads(out)["data"]["count"] == len(C) and err == ""
    code, out, _ = cli("check", "aios.fs.read", "nope.tool", tmp_path=tmp_path)
    assert code == 1 and "MISSING" in out                                  # exit code reaches the shell
    code, _, err = cli("list", "--category", "bad", tmp_path=tmp_path)
    assert code == 2 and "TOOLCLI_ERR_USAGE" in err and "Traceback" not in err
    code, out, _ = cli("export", tmp_path=tmp_path)
    assert code == 0 and out.strip() == C.export_json()


def test_cli_and_mcp_agree_on_every_name(tmp_path):
    from aiosh_mcp import tool_registry_cli
    get_tool = {t.name: t for t in server_app._tool_manager.list_tools()}["aios_tool_registry_get"]
    names = [n for n in C.names()] + ["pentest.newthing", "aios.unknown.x"]
    for name in names:
        via_cli = tool_registry_cli.dispatch_cli(["get", name]).data
        via_mcp = get_tool.fn(name=name)["data"]
        assert via_cli == via_mcp, name


def test_cli_never_touches_the_audit_db(tmp_path):
    cli("list", tmp_path=tmp_path)
    cli("decide", "pentest.nmap", "--mode", "strict", tmp_path=tmp_path)
    assert not (tmp_path / "audit.db").exists()                            # read-only surface (TOOLCLI-INV1)


@pytest.mark.skipif(shutil.which("node") is None or not TS_PEP.exists(), reason="node or aiosh-cli dist missing")
def test_exported_catalog_parity_with_ts(tmp_path):
    exported = tmp_path / "catalog.json"
    code, _, _ = cli("export", "--out", str(exported), tmp_path=tmp_path)
    assert code == 0
    probe = tmp_path / "probe.mjs"
    probe.write_text(
        "import { readFileSync } from 'node:fs';\n"
        f"import {{ isIrreversible, toolGlobMatch }} from {json.dumps(TS_PEP.as_uri())};\n"
        f"const cat = JSON.parse(readFileSync({json.dumps(str(exported))}, 'utf8'));\n"
        "const out = cat.entries.map(e => [e.canonical, isIrreversible(e.canonical),\n"
        "  toolGlobMatch(e.canonical, [e.canonical.split('.')[0] + '.*'])]);\n"
        "console.log(JSON.stringify({schema: cat.schema_version, rows: out}));\n", encoding="utf-8")
    out = subprocess.run(["node", str(probe)], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-1000:]
    data = json.loads(out.stdout.strip().splitlines()[-1])
    assert data["schema"] == 1 and len(data["rows"]) == len(C)
    for canonical, ts_irrev, ts_glob in data["rows"]:
        entry = C.get(canonical)
        assert ts_irrev == entry.irreversible or (entry.irreversible and not ts_irrev), canonical   # catalog may be stricter
        py_glob = audit_client.tool_glob_match(canonical, [canonical.split(".")[0] + ".*"])
        assert ts_glob == py_glob, canonical                                  # same glob semantics both sides
