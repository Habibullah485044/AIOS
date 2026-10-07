#!/usr/bin/env python3
"""Proof of Restraint: Continuous Restraint Conformance — Unit Test Verification (T-02886).

Sprint / Architecture: ADR-0037 (I-5), Invariant I-5.
Contract: docs/tasks/evidence/T-02883-spec.md.

Unit-level verification of the CRCS harness itself (meta-tests):
  M1  battery criteria map complete: CRITERIA == C1..C6, every criterion mapped
  M2  every mapped node id resolves to a real test callable in the suite module
  M3  no orphaned conformance tests: every test_c* in the suite is battery-mapped
  M4  fail-closed runner: unmapped criterion => run_criterion() returns False
  M5  sandbox isolation: conform_env never touches the real AIOSH_HOME/audit.db
  M6  contract fixtures: F-* fixture identifiers from T-02883 exist in the suite
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO))

TOOLS = REPO / "tools"
SUITE_PATH = HERE / "test_por_conformance.py"
BATTERY_PATH = TOOLS / "test_por_conformance_suites.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"cannot load {path}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def crcs():
    return _load(SUITE_PATH, "crcs_suite_under_test")


@pytest.fixture(scope="module")
def battery():
    return _load(BATTERY_PATH, "crcs_battery_under_test")


def test_m1_battery_criteria_map_complete(battery):
    assert battery.CRITERIA == ("C1", "C2", "C3", "C4", "C5", "C6")
    for criterion in battery.CRITERIA:
        nodes = battery.CRITERIA_TESTS.get(criterion)
        assert nodes, f"criterion {criterion} has no mapped test nodes"
        assert all(isinstance(n, str) and n.startswith("test_") for n in nodes)


def test_m2_mapped_nodes_resolve_to_real_tests(battery, crcs):
    for criterion, nodes in battery.CRITERIA_TESTS.items():
        for node in nodes:
            fn = getattr(crcs, node, None)
            assert callable(fn), f"{criterion}: node '{node}' does not exist in the suite module"
            assert node.startswith("test_"), f"{criterion}: node '{node}' is not a test function"


def test_m3_no_orphaned_conformance_tests(battery, crcs):
    defined = {name for name in dir(crcs)
               if name.startswith("test_c") and callable(getattr(crcs, name))}
    mapped = {node for nodes in battery.CRITERIA_TESTS.values() for node in nodes}
    orphans = defined - mapped
    assert not orphans, f"conformance tests not enforced by the battery: {sorted(orphans)}"
    phantom = mapped - defined
    assert not phantom, f"battery maps non-existent tests: {sorted(phantom)}"


def test_m4_runner_fail_closed_on_unmapped_criterion(battery):
    assert battery.run_criterion("C99", verbose=False) is False
    assert battery.run_criterion("", verbose=False) is False


def test_m5_sandbox_isolation(crcs):
    """The conformance sandbox must run against a temp AIOSH_HOME,
    never the real one, and restore the environment on cleanup."""
    before = os.environ.get("AIOSH_HOME")
    env, cleanup = crcs._make_env()
    try:
        home = Path(os.environ["AIOSH_HOME"])
        assert home.exists(), "sandbox AIOSH_HOME must exist"
        assert "por-conform-" in str(home), f"unexpected AIOSH_HOME: {home}"
        assert Path(env["db_path"]).is_relative_to(home), "audit.db must live inside the sandbox"
        assert Path(env["anchors_path"]).is_relative_to(home), "anchors must live inside the sandbox"

        real_home = Path(os.environ.get("HOME") or os.environ.get("USERPROFILE") or "") / ".aios"
        if real_home.exists():
            assert Path(env["db_path"]) != real_home / "audit.db", "must not touch the real audit.db"
    finally:
        cleanup()
    assert os.environ.get("AIOSH_HOME") == before, "cleanup must restore AIOSH_HOME"


def test_m6_contract_fixture_identifiers(crcs):
    """F-* fixture identifiers from T-02883-spec.md §3 exist in the suite."""
    assert crcs.GRANT_UNTOUCHED == "gr_conform_untouched"   # F-UNTOUCHED
    assert crcs.GRANT_REDEEMED == "gr_conform_redeemed"     # F-REDEEMED
    assert crcs.WINDOW_START < crcs.WINDOW_END              # F-ANCHOR-CADENCE window
    assert callable(crcs._forge_proof)                      # F-REDEEMED forgeries (C4.2)
    assert callable(crcs._ts_canonical_json)                # F-PARITY (C5)
