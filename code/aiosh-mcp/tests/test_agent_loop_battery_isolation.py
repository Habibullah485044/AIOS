"""Security guard for the agent-loop test battery (T-03319; AUTOTEST-INV3).

1. Production code never references the test doubles (``AllowAllGate`` allows everything).
2. The test directory is not packaged with ``aiosh_mcp``.
3. A representative slice of the battery, run with HOME / AIOSH_HOME pointed at an empty
   sentinel directory, writes nothing there and leaves no artefacts in the working tree.
"""

import os
import subprocess
import sys
import tomllib
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parents[1]
PKG = PKG_ROOT / "aiosh_mcp"
TEST_ONLY_NAMES = ("AllowAllGate", "agent_loop_grants", "agent_loop_model", "mint_grant")


def test_production_code_never_references_test_doubles():
    offenders = [f"{p.name}: {name}" for p in PKG.glob("*.py") for name in TEST_ONLY_NAMES
                 if name in p.read_text(encoding="utf-8")]
    assert offenders == []


def test_tests_are_not_packaged():
    meta = tomllib.loads((PKG_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    include = meta["tool"]["setuptools"]["packages"]["find"]["include"]
    assert include == ["aiosh_mcp*"]
    assert not (PKG / "tests").exists()


def test_battery_slice_never_touches_home_or_tree(tmp_path):
    sentinel = tmp_path / "sentinel-home"
    sentinel.mkdir()
    env = dict(os.environ, HOME=str(sentinel), USERPROFILE=str(sentinel), AIOSH_HOME=str(sentinel),
               AIOSH_LOOP_FUZZ_SEEDS="11", AIOSH_LOOP_FUZZ_OPS="60")
    before = set(p for p in PKG_ROOT.rglob("*") if "__pycache__" not in p.parts and ".pytest_cache" not in p.parts)
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
         "tests/test_agent_loop_fuzz.py", "tests/test_agent_loop_cli_integration.py",
         "tests/test_agent_loop_core_service_integration.py", "tests/test_agent_loop_data_model_integration.py"],
        cwd=PKG_ROOT, env=env, capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stdout[-2000:]
    assert list(sentinel.iterdir()) == [], "a test wrote to the default AIOSH_HOME"
    after = set(p for p in PKG_ROOT.rglob("*") if "__pycache__" not in p.parts and ".pytest_cache" not in p.parts)
    assert sorted(map(str, after - before)) == [], "a test left artefacts in the package tree"
