#!/usr/bin/env python3
"""Continuous Restraint Conformance Suite — criteria battery runner (T-02884 SCAFFOLD).

Sprint / Architecture: ADR-0037 (I-5), Invariant I-5.
Contract: docs/tasks/evidence/T-02883-spec.md.

Criteria battery C1..C6 mirroring tools/test_fs_layout_suites.py style:
executes the conformance scenarios and prints a per-criterion PASS/FAIL
report. Exit 0 only when every criterion passes (fail-closed).

Usage:
  python3 tools/test_por_conformance_suites.py

Implementation: T-02885. Each criterion runs its pytest node ids in
sequence (skip-safe); a criterion passes only when pytest exits 0.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

TESTS = REPO / "code" / "aiosh-mcp" / "tests"
SUITE = TESTS / "test_por_conformance.py"

CRITERIA = ("C1", "C2", "C3", "C4", "C5", "C6")

# Bounded external-process execution (T-02889 hardening).
CRITERION_TIMEOUT_S = 900


def _skipped_count(stdout: str) -> int:
    """Extract pytest's skipped-node count from its summary line (TV-CRC-05)."""
    m = re.search(r"(\d+) skipped", stdout)
    return int(m.group(1)) if m else 0


def _criterion_verdict(returncode: int, skipped: int, strict: bool) -> bool:
    """Fail-closed verdict: any pytest failure fails the criterion; any skip
    fails it too in strict mode (AIOSH_CONFORMANCE_STRICT=1). Never silent:
    skips are always reported by run_criterion."""
    if returncode != 0:
        return False
    if strict and skipped:
        return False
    return True

# criterion -> pytest node ids implementing it (T-02885 maps these)
CRITERIA_TESTS: dict[str, tuple[str, ...]] = {
    "C1": ("test_c1_no_grant_consequential_tool_refused",
           "test_c1_spent_grant_replay_refused",
           "test_c1_consequential_tool_coverage_complete"),
    "C2": ("test_c2_mint_redeem_row_parity",
           "test_c2_canonical_json_parity"),
    "C3": ("test_c3_untouched_grant_proves_restrained",
           "test_c3_standalone_verify_valid",
           "test_c3_idempotent_verdict"),
    "C4": ("test_c4_redeemed_grant_prove_refused",
           "test_c4_forged_restraint_proof_rejected"),
    "C5": ("test_c5_python_typescript_verdict_parity",
           "test_c5_canonical_json_byte_parity"),
    "C6": ("test_c6_anchor_chain_verifies",
           "test_c6_window_bounding_between_anchors"),
}


def run_criterion(criterion: str, verbose: bool = True) -> bool:
    """Run one criterion's test nodes. Returns True iff all pass (fail-closed).

    T-02889 hardening: bounded subprocess timeout (fail-closed on hang),
    skip-transparency (skips always reported, never silently green), and
    strict mode (AIOSH_CONFORMANCE_STRICT=1) where any skip fails the
    criterion — honest disclosure per ADR-0035 §F-2.
    """
    nodes = CRITERIA_TESTS.get(criterion, ())
    if not nodes:
        print(f"{criterion}: no test nodes mapped")
        return False
    cmd = [sys.executable, "-m", "pytest", "-q", "--no-header", "-rs",
           "-p", "no:cacheprovider"] + [f"{SUITE}::{n}" for n in nodes]
    strict = os.environ.get("AIOSH_CONFORMANCE_STRICT") == "1"
    try:
        proc = subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True,
                              timeout=CRITERION_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        print(f"    ! FAIL: criterion timed out after {CRITERION_TIMEOUT_S}s")
        return False
    except OSError as e:
        print(f"    ! FAIL: could not execute pytest: {e}")
        return False
    if verbose and proc.stdout:
        tail = proc.stdout.strip().splitlines()
        for line in tail[-4:]:
            print(f"    {line}")
    if proc.returncode != 0 and proc.stderr:
        for line in proc.stderr.strip().splitlines()[-6:]:
            print(f"    ! {line}")
    skipped = _skipped_count(proc.stdout)
    if skipped:
        for line in proc.stdout.splitlines():
            if "SKIPPED" in line:
                print(f"    ~ {line.strip()}")
        if strict:
            print(f"    ! FAIL: {skipped} skipped node(s) under AIOSH_CONFORMANCE_STRICT=1")
        else:
            print(f"    ~ {skipped} skipped node(s) treated as pass "
                  "(set AIOSH_CONFORMANCE_STRICT=1 to fail on skips)")
    return _criterion_verdict(proc.returncode, skipped, strict)


def main() -> int:
    print("Continuous Restraint Conformance Suite (CRCS) — Invariant I-5")
    strict = os.environ.get("AIOSH_CONFORMANCE_STRICT") == "1"
    print(f"mode: {'STRICT (skips fail)' if strict else 'skip-transparent'}; "
          f"timeout: {CRITERION_TIMEOUT_S}s per criterion")
    print("=" * 64)
    failed: list[str] = []
    for criterion in CRITERIA:
        ok = run_criterion(criterion)
        print(f"{criterion}: {'PASS' if ok else 'FAIL'}")
        if not ok:
            failed.append(criterion)
    print("=" * 64)
    if failed:
        print(f"NON-CONFORMANT: {', '.join(failed)}")
        return 1
    print("CONFORMANT: C1..C6 PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
