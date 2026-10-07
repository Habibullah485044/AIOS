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

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent

TESTS = REPO / "code" / "aiosh-mcp" / "tests"
SUITE = TESTS / "test_por_conformance.py"

CRITERIA = ("C1", "C2", "C3", "C4", "C5", "C6")

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
    """Run one criterion's test nodes. Returns True iff all pass (fail-closed)."""
    nodes = CRITERIA_TESTS.get(criterion, ())
    if not nodes:
        print(f"{criterion}: no test nodes mapped")
        return False
    cmd = [sys.executable, "-m", "pytest", "-q", "--no-header",
           "-p", "no:cacheprovider"] + [f"{SUITE}::{n}" for n in nodes]
    proc = subprocess.run(cmd, cwd=str(REPO), capture_output=True, text=True)
    if verbose and proc.stdout:
        tail = proc.stdout.strip().splitlines()
        for line in tail[-4:]:
            print(f"    {line}")
    if proc.returncode != 0 and proc.stderr:
        for line in proc.stderr.strip().splitlines()[-6:]:
            print(f"    ! {line}")
    return proc.returncode == 0


def main() -> int:
    print("Continuous Restraint Conformance Suite (CRCS) — Invariant I-5")
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
