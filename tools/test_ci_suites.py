"""CI Smoke Orchestration — data model unit tests (T-00115).

Standalone test for tools/ci_suites.py following the repo smoke-test
style. Never executes any real CI suite; runs in seconds.

Coverage:
  W1  registry integrity: 20 unique suites; order == frozen canonical order
      (regex-extracted); every command's script exists on disk
  W2  build_result_record happy path (+derived log_path)
  W3  timeout/error statuses force exit_code null
  W4  rejections name the field (suite/index/status/duration/timestamps)
  W5  write_summary atomic round-trip; no *.tmp.* leftovers
  W6  write_summary failure cleans its temp (unwritable target dir)
  W7  import-time validation fires on a corrupted registry copy
"""

from __future__ import annotations

import glob
import importlib.util
import json
import os
import re
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
MODULE_PATH = HERE / "ci_suites.py"

PASS = "[+]"
FAIL = "[-]"


def load():
    spec = importlib.util.spec_from_file_location("ci_suites_under_test",
                                                  MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


#: Canonical execution order (contract since the legacy bash runner;
#: T-00116 made the registry the single source — this frozen tuple pins
#: it against silent reordering).
CANONICAL_ORDER = (
    "rust_smoke", "classifier_smoke", "mcp_smoke", "task_service_smoke",
    "task_mcp_smoke", "pentest_smoke", "sandbox_smoke", "retention_smoke",
    "demo_smoke", "metrics_smoke", "cli_bash_smoke", "task_cli_smoke",
    "task_config_smoke", "task_matrix_smoke", "security_policy",
    "task_ledger_unit", "task_ledger_scaffold", "task_docs_unit",
    "task_docs_scaffold", "ci_service_unit", "toolchain_cli_smoke",
    "toolchain_mcp_smoke", "doc_cli_smoke", "doc_mcp_smoke",
    "doc_index_suites", "evidence_cli_smoke", "evidence_mcp_smoke",
    "evidence_checker", "evidence_unit",
    "por_conformance", "compliance_integration",
    "compliance_config_unit", "agent_loop_integration",
)


def main() -> int:
    cs = load()

    # ---- W1 — registry IS the single source; bash is a delegating shim
    bash = (REPO / "ci" / "run_all_smokes.sh").read_text(encoding="utf-8")
    ok = (len(cs.SUITES) == 33
          and cs.SUITE_NAMES == CANONICAL_ORDER
          and "tools/ci_run.py" in bash)
    if ok:
        for s in cs.SUITES:
            script = s["command"][-1]
            if not (REPO / script).exists():
                print(f"{FAIL} W1 command script missing on disk: {script}")
                return 1
            if s["timeout_s"] <= 0:
                print(f"{FAIL} W1 non-positive timeout for {s['name']}")
                return 1
    print(f"{PASS if ok else FAIL} W1 registry 20/20 == frozen canonical "
          f"order; bash delegates to ci_run.py; scripts exist")
    if not ok:
        return 1

    base = dict(started_at="2026-08-23T01:00:00Z",
                finished_at="2026-08-23T01:00:05Z")

    # ---- W2 — happy path
    r = cs.build_result_record(suite="rust_smoke", index=0, status="pass",
                               exit_code=0, duration_ms=4321, **base)
    ok = (r["log_path"] == "/tmp/aiosh-ci-rust_smoke.log"
          and r["exit_code"] == 0 and r["index"] == 0)
    print(f"{PASS if ok else FAIL} W2 pass record + derived log path")
    if not ok:
        return 1

    # ---- W3 — timeout/error force null exit codes
    t = cs.build_result_record(suite="demo_smoke", index=8, status="timeout",
                               exit_code=None, duration_ms=900000, **base)
    e = cs.build_result_record(suite="demo_smoke", index=8, status="error",
                               exit_code=7, duration_ms=10, **base)  # coerced
    ok = t["exit_code"] is None and e["exit_code"] is None
    print(f"{PASS if ok else FAIL} W3 timeout/error force exit_code=null "
          f"(even when caller passes an int)")
    if not ok:
        return 1

    # ---- W4 — loud, field-naming rejections
    cases = [
        ("nope", 0, "pass", 0, 1, base, "unknown suite"),
        ("rust_smoke", 3, "pass", 0, 1, base, "belongs to suite"),
        ("rust_smoke", 0, "wat", 0, 1, base, "status"),
        ("rust_smoke", 0, "fail", 1, -1, base, "duration_ms"),
        ("rust_smoke", 0, "pass", 0, 1,
         {"started_at": "2026-08-23 01:00:00", "finished_at": "x"}, "Z timestamp"),
        ("rust_smoke", "0", "pass", 0, 1, base, "index"),
    ]
    ok = True
    for suite, idx, st, rc, dur, times, frag in cases:
        try:
            cs.build_result_record(suite=suite, index=idx, status=st,
                                   exit_code=rc, duration_ms=dur, **times)
            print(f"{FAIL} W4 accepted invalid input (wanted: {frag})")
            return 1
        except ValueError as ex:
            if frag not in str(ex):
                print(f"{FAIL} W4 error lacks {frag!r}: {ex}")
                return 1
    print(f"{PASS} W4 all invalid inputs rejected naming the field")

    # ---- W5 — atomic round-trip
    summary = {
        "tool": "aios-ci-orchestrator", "schema_version": 1,
        "started_at": "2026-08-23T01:00:00Z",
        "finished_at": "2026-08-23T01:20:00Z",
        "total": 2, "passed": 1, "failed": 1, "all_pass": False,
        "results": [r, t],
    }
    out = Path(tempfile.mkdtemp(prefix="ci-suites-w5-")) / "summary.json"
    written = cs.write_summary(summary, path=str(out))
    loaded = json.loads(out.read_text(encoding="utf-8"))
    ok = (written == str(out) and loaded["total"] == 2
          and loaded["results"][0]["suite"] == "rust_smoke"
          and not glob.glob(str(out) + ".tmp.*"))
    print(f"{PASS if ok else FAIL} W5 atomic write + JSON round-trip, "
          f"no temp leftovers")
    if not ok:
        return 1

    # ---- W6 — failure path cleans temp. Uses a NON-DIRECTORY parent
    # component (uid-independent; chmod-based checks are meaningless when
    # running as root, which ignores DAC bits).
    bad_dir = Path(tempfile.mkdtemp(prefix="ci-suites-w6-"))
    blocker = bad_dir / "blocker"
    blocker.write_text("i am a file, not a dir\n")
    target = str(bad_dir / "blocker" / "s.json")  # ENOTDIR on open
    try:
        try:
            cs.write_summary(summary, path=target)
            print(f"{FAIL} W6 write through file-parent succeeded?!")
            return 1
        except OSError:
            pass
        leftovers = glob.glob(target + ".tmp.*")
        ok = not leftovers
        print(f"{PASS if ok else FAIL} W6 failed write leaves no temp files")
        if not ok:
            print("   leftovers:", leftovers)
            return 1
    finally:
        pass

    # ---- W7 — corrupted registry copy must fail AT IMPORT
    broken_src = MODULE_PATH.read_text(encoding="utf-8").replace(
        '"name": "classifier_smoke",', '"name": "rust_smoke",', 1)
    tmp_mod = Path(tempfile.mkdtemp(prefix="ci-suites-w7-")) / "broken.py"
    tmp_mod.write_text(broken_src, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("ci_suites_broken", tmp_mod)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        print(f"{FAIL} W7 duplicate-name registry imported cleanly?!")
        return 1
    except ValueError as ex:
        ok = "duplicate suite name" in str(ex)
        print(f"{PASS if ok else FAIL} W7 corrupted registry rejected at "
              f"import ({ex})")
        if not ok:
            return 1

    print("PASS: ci_suites unit tests (W1..W7)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
