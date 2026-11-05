"""Documentation drift test for Agent Loop Hardening (T-03347; LOOPDOC-INV1 / INV3).

The operator doc must mention every public identifier the code defines, and every runnable
example in it must still work. Fails CI the moment code and docs diverge.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from aiosh_mcp import agent_loop_doc as doc
from aiosh_mcp.agent_loop_cli import load_plan
from aiosh_mcp.agent_loop_config import validate
from aiosh_mcp.server import mcp

PKG_ROOT = Path(__file__).resolve().parents[1]
SPEC = PKG_ROOT.parents[1] / "docs" / "SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE.md"
TEXT = SPEC.read_text(encoding="utf-8")
REF = doc.reference()


def blocks(lang):
    return re.findall(rf"```{lang}\n(.*?)```", TEXT, re.S)


@pytest.mark.parametrize("kind,items", [
    ("error code", [e["code"] for e in REF["errors"]]),
    ("MCP tool", [t["name"] for t in REF["tools"]]),
    ("config key", [f["key"] for f in REF["config"]["fields"]]),
    ("config env", [f["env"] for f in REF["config"]["fields"]]),
    ("locked key", REF["config"]["locked_keys"]),
    ("CLI subcommand", [c["subcommand"] for c in REF["cli"]]),
])
def test_every_identifier_is_documented(kind, items):
    missing = [i for i in items if f"`{i}`" not in TEXT and f" {i} " not in TEXT and f"{i}(" not in TEXT
               and f"cli {i}" not in TEXT]
    assert missing == [], f"undocumented {kind}(s) in {SPEC.name}: {missing}"


def test_documented_codes_exist():
    """The reverse direction: no code in the doc's tables that the code no longer defines."""
    documented = set(re.findall(r"`((?:LOOP[A-Z]*|AGENTLOOPCONF)_ERR_[A-Z_]+)`", TEXT))
    stale = sorted(documented - set(doc.ERROR_MEANINGS))
    assert stale == [], f"doc mentions removed codes: {stale}"


@pytest.mark.parametrize("index", range(len(blocks("python"))))
def test_python_examples_run(index, tmp_path):
    code = blocks("python")[index]
    proc = subprocess.run([sys.executable, "-c", code], cwd=PKG_ROOT, capture_output=True, text=True, timeout=120,
                          env=dict(os.environ, AIOSH_HOME=str(tmp_path)))
    assert proc.returncode == 0, proc.stderr[-1500:]


def test_json_examples_are_valid():
    tools = {t.name: t for t in mcp._tool_manager.list_tools()}
    checked = {"tool_call": 0, "plan": 0, "config": 0}
    for raw in blocks("json"):
        data = json.loads(raw)
        if "name" in data and "arguments" in data:
            assert data["name"] in tools, data["name"]
            tools[data["name"]].fn_metadata.arg_model.model_validate(data["arguments"])   # published schema
            checked["tool_call"] += 1
        elif "turns" in data:
            p = PKG_ROOT / ".doc_plan.json"
            try:
                p.write_text(raw, encoding="utf-8")
                assert load_plan(str(p))
            finally:
                p.unlink(missing_ok=True)
            checked["plan"] += 1
        else:
            validate(data)            # raises on unknown / locked keys
            checked["config"] += 1
    assert all(checked.values()), checked
