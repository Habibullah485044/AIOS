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

T-02889 hardening verification:
  H1  skip transparency + strict-mode fail-closed verdict (TV-CRC-05)
  H2  interpreter resolution: override trust, PATH lookup, loud failure (TV-CRC-01)
  H3  sandbox AIOSH_HOME via monkeypatch, never global env (TV-CRC-04)
  H4  temp-root registration/release, atexit hygiene (TV-CRC-07)
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


# ---------------------------------------------------------------------------
# T-02889 hardening verification
# ---------------------------------------------------------------------------
class _StubMP:
    """Records setenv calls without touching the global environment."""

    def __init__(self):
        self.setenv_calls: list[tuple[str, str]] = []

    def setenv(self, key: str, value: str) -> None:
        self.setenv_calls.append((key, value))


def test_hardened_h1_skip_transparency_and_strict_verdict(battery):
    """H1 / TV-CRC-05: skips are parsed and reported; strict mode is fail-closed."""
    assert battery._skipped_count("3 passed, 2 skipped in 0.50s") == 2
    assert battery._skipped_count("5 passed in 0.50s") == 0
    assert battery._skipped_count("") == 0
    assert battery._criterion_verdict(0, 0, False) is True
    assert battery._criterion_verdict(0, 1, False) is True    # surfaced, not silently green
    assert battery._criterion_verdict(0, 1, True) is False    # strict: any skip fails
    assert battery._criterion_verdict(1, 0, False) is False
    assert battery._criterion_verdict(1, 1, True) is False


def test_hardened_h2_interpreter_resolution(crcs, monkeypatch):
    """H2 / TV-CRC-01: override is trusted verbatim; PATH resolution lands on a
    real file; unresolvable interpreters fail loudly."""
    monkeypatch.setenv("AIOSH_NODE", "explicit-node-override")
    assert crcs._resolve_interpreter("node", "AIOSH_NODE") == ["explicit-node-override"]

    monkeypatch.delenv("AIOSH_NODE")
    if not os.environ.get("PATH"):
        pytest.skip("no PATH to resolve against")
    try:
        argv = crcs._resolve_interpreter("node", "AIOSH_NODE")
    except FileNotFoundError:
        pytest.skip("node not on PATH")
    assert Path(argv[0]).is_file(), "resolved interpreter must be a real file"

    monkeypatch.delenv("AIOSH_NODE_ABSENT", raising=False)
    with pytest.raises(FileNotFoundError):
        crcs._resolve_interpreter("definitely-not-a-real-interpreter-xyz",
                                 "AIOSH_NODE_ABSENT")


def test_hardened_h3_sandbox_uses_monkeypatch_not_global_env(crcs):
    """H3 / TV-CRC-04: with a monkeypatch supplied, the global AIOSH_HOME
    environment is never mutated by the sandbox factory."""
    before = os.environ.get("AIOSH_HOME")
    mp = _StubMP()
    env, cleanup = crcs._make_env(mp)
    try:
        assert mp.setenv_calls and mp.setenv_calls[0][0] == "AIOSH_HOME"
        assert mp.setenv_calls[0][1] == str(env["aiosh_home"])
        assert os.environ.get("AIOSH_HOME") == before, \
            "global env must be untouched when a monkeypatch is supplied"
    finally:
        cleanup()


def test_hardened_h4_temp_roots_registered_and_released(crcs):
    """H4 / TV-CRC-07: sandboxes register with the atexit registry and are
    removed + unregistered on cleanup."""
    env, cleanup = crcs._make_env()
    tmp = env["aiosh_home"].parent
    try:
        assert tmp in crcs._TEMP_ROOTS, "sandbox root must be tracked for atexit hygiene"
    finally:
        cleanup()
    assert tmp not in crcs._TEMP_ROOTS, "cleanup must release the tracking slot"
    assert not tmp.exists(), "cleanup must remove the sandbox tree"
