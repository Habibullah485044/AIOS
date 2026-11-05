"""Doc drift test for the tool registry (T-03371): the operator doc stays true to the code."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from aiosh_mcp import tool_registry_data_model as reg
from aiosh_mcp.server import mcp

PKG_ROOT = Path(__file__).resolve().parents[1]
DOC = PKG_ROOT.parents[1] / "docs" / "SPEC-TOOL-REGISTRY-DATA-MODEL.md"
TEXT = DOC.read_text(encoding="utf-8")


def test_every_error_code_documented_both_ways():
    from aiosh_mcp import tool_registry_service as svc
    codes = {v for mod in (reg, svc) for k, v in vars(mod).items() if k.startswith(("TOOLREG_ERR_", "TOOLSVC_ERR_"))}
    documented = set(re.findall(r"`((?:TOOLREG|TOOLSVC)_ERR_[A-Z_]+)`", TEXT))
    assert codes == documented


def test_enums_and_counts_documented():
    for enum_cls in (reg.Category, reg.Effect, reg.ScopeKind):
        for member in enum_cls:
            assert f"`{member.value}`" in TEXT, member
    assert f"**{len(reg.default_catalog())} entries**" in TEXT


PY_BLOCKS = re.findall(r"```python\n(.*?)```", TEXT, re.S)


@pytest.mark.parametrize("block", PY_BLOCKS, ids=[f"example{i}" for i in range(len(PY_BLOCKS))])
def test_python_example_runs_and_prints_what_the_doc_says(tmp_path, block):
    expected = [line.split("# -> ", 1)[1] for line in block.splitlines() if "# -> " in line]
    env = {k: v for k, v in os.environ.items() if k != "AIOSH_TOOL_REGISTRY_MODE"}
    out = subprocess.run([sys.executable, "-c", block], cwd=PKG_ROOT, capture_output=True, text=True, timeout=120,
                         env=dict(env, AIOSH_HOME=str(tmp_path)))
    assert out.returncode == 0, out.stderr[-1500:]
    assert out.stdout.split("\n")[:len(expected)] == expected


def test_json_tool_calls_match_the_live_schema():
    tools = {t.name: t for t in mcp._tool_manager.list_tools()}
    calls = [json.loads(b) for b in re.findall(r"```json\n(.*?)```", TEXT, re.S)]
    assert calls
    for call in calls:
        tools[call["name"]].fn_metadata.arg_model.model_validate(call["arguments"])
