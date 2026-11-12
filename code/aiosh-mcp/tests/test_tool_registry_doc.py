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
    from aiosh_mcp import tool_registry_cli as cli
    from aiosh_mcp import tool_registry_config as conf
    codes = {v for mod in (reg, svc, cli, conf) for k, v in vars(mod).items()
             if k.startswith(("TOOLREG_ERR_", "TOOLSVC_ERR_", "TOOLCLI_ERR_", "TOOLREGCONF_ERR_"))}
    documented = set(re.findall(r"`((?:TOOLREG|TOOLSVC|TOOLCLI|TOOLREGCONF)_ERR_[A-Z_]+)`", TEXT))
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
    calls = [c for c in (json.loads(b) for b in re.findall(r"```json\n(.*?)```", TEXT, re.S)) if "name" in c]
    assert calls
    for call in calls:
        tools[call["name"]].fn_metadata.arg_model.model_validate(call["arguments"])


CLI_LINES = [line for block in re.findall(r"```bash\n(.*?)```", TEXT, re.S) for line in block.splitlines()
             if line.startswith("python -m aiosh_mcp.tool_registry_cli")]


@pytest.mark.parametrize("line", CLI_LINES)
def test_documented_cli_commands_run_with_the_stated_exit_code(line, tmp_path):
    import shlex
    command, _, comment = line.partition("#")
    expected = int(re.search(r"exit (\d+)", comment).group(1))
    env = {k: v for k, v in os.environ.items() if k != "AIOSH_TOOL_REGISTRY_MODE"}
    out = subprocess.run([sys.executable, *shlex.split(command)[1:]], cwd=PKG_ROOT, capture_output=True, text=True,
                         timeout=120, env=dict(env, AIOSH_HOME=str(tmp_path)))
    assert out.returncode == expected, (line, out.stderr[-500:])
    assert "Traceback" not in out.stderr


def test_every_cli_subcommand_is_documented():
    from aiosh_mcp import tool_registry_cli as cli
    assert len(CLI_LINES) >= len(cli.SUBCOMMANDS)
    for sub in cli.SUBCOMMANDS:
        assert any(f"tool_registry_cli {sub}" in line for line in CLI_LINES), sub



def test_documented_annotation_policy_matches_the_code():
    from aiosh_mcp import tool_registry_api as api
    from aiosh_mcp.server import mcp as server_app
    for category in api.READ_ONLY_HINT_CATEGORIES:
        assert f"`{category}`" in TEXT, category
    for param in ("grant_id", "caller_grant_id", "capability_token", "token"):
        assert f"`{param}`" in TEXT, param
    served = server_app._tool_manager.list_tools()
    read_only = sum(1 for t in served if t.annotations and t.annotations.readOnlyHint)
    assert f"all **{len(served)}** tools are annotated" in TEXT and f"**{read_only}** are advertised read-only" in TEXT



def test_documented_config_matches_the_code(tmp_path, monkeypatch):
    from aiosh_mcp import tool_registry_config as conf
    for key, field in conf.FIELDS.items():
        assert f"| `{key}` | {field.default} | {field.lo}..{field.hi} | `{field.env}` |" in TEXT, key
    for key in conf.LOCKED_KEYS:
        assert f"`{key}`" in TEXT, key
    example = next(json.loads(b) for b in re.findall(r"```json\n(.*?)```", TEXT, re.S) if "mode" in b and "name" not in b)
    path = tmp_path / "c.json"
    path.write_text(json.dumps(example), encoding="utf-8")
    monkeypatch.setenv(conf.ENV_CONFIG, str(path))
    resolved = conf.resolve()
    assert resolved["errors"] == [] and resolved["config"] == example     # the documented example is valid as written


def test_documented_automated_tests_match_the_helpers(monkeypatch):
    """§6f stays true to the test helpers (T-03421): knob table, defaults, grace period, file names, drift lists."""
    import tool_registry_model as M
    import test_tool_registry_rust_drift as D
    section = TEXT.split("## 6f.", 1)[1].split("\n## ", 1)[0]
    assert f"| `AIOSH_TOOLREG_FUZZ_SEEDS` | 1,2,3 | 1..{M.MAX_SEEDS} integer seeds |" in section
    assert f"| `AIOSH_TOOLREG_FUZZ_N` | 300 | 1..{M.MAX_CASES} cases per property and seed |" in section
    assert (f"| `AIOSH_TOOLREG_FUZZ_TIMEOUT_S` | {M.DEFAULT_TIMEOUT_S:g} | (0, {M.MAX_TIMEOUT_S:g}] seconds per property "
            f"test |") in section
    for var in ("AIOSH_TOOLREG_FUZZ_SEEDS", "AIOSH_TOOLREG_FUZZ_N", "AIOSH_TOOLREG_FUZZ_TIMEOUT_S"):
        monkeypatch.delenv(var, raising=False)
    assert (M.seeds(), M.n_cases(), M.timeout_s()) == ([1, 2, 3], 300, M.DEFAULT_TIMEOUT_S)   # the documented defaults
    assert f"killed {M.HARD_KILL_GRACE_S:g} s later" in section
    named = set(re.findall(r"(test_tool_registry_[a-z_]+\.py)", section))
    assert named and all((PKG_ROOT / "tests" / name).is_file() for name in named), named
    assert D.RUST_WEAKER == {"pentest.tshark"} and D.CATALOG_WEAKER == set()
    assert "Rust weaker: `pentest.tshark`; catalog weaker: none" in section
    for prop in ("P1", "P2", "P3", "P4", "P5", "P6"):
        assert f"| {prop} |" in section, prop
