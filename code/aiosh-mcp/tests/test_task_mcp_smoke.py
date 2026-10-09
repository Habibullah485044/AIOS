#!/usr/bin/env python3
"""Task Ledger Control MCP/API surface (Python reference) — smoke T-00045.

Exercises the registered `aios_task` tool function directly against a
fully isolated sandbox (temp AIOSH_TASKS_DIR + AIOSH_HOME; grant minted
via the Rust CLI against the same audit DB), asserting observable
behavior: envelopes, ledger files, event log, evidence stubs.

  P1 valid read: status envelope
  P2 valid mutation: done observables (pointer/event/stub)
  P3 invalid: unknown action refused pre-gate
  P4 invalid: empty note refused pre-gate
  P5 boundary: oversized note refused
  P6 gate: mutation without grant -> pep refusal, audited
  P7 primary failure mode: NO-SKIP, zero state change
  P8 rebuild replay: skip survives rebuild (D4 parity)
"""

import json
import os
import subprocess
import sys

# T-02902: pin stdout/stderr to UTF-8 — this suite prints non-ASCII
# markers that the Windows ANSI codepage (cp1252) cannot encode.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
def _rust_bin(name: str) -> Path:
    """Resolve a debug binary, tolerating the Windows .exe suffix (T-02902)."""
    base = REPO / "code" / "aiosh-rust" / "target" / "debug" / name
    exe = base.with_name(base.name + ".exe")
    return exe if os.name == "nt" and exe.exists() else base

BIN = _rust_bin("aiosh")

PASS, FAIL = "[✓]", "[✗]"
MAX_NOTE = 4096


def make_ledger(path: Path, n: int = 4) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for i in range(1, n + 1):
            f.write(json.dumps({
                "id": i, "title": f"task {i}", "phase": "Phase 0 — Test",
                "status": "pending", "goal": f"g{i}", "instructions": [f"s{i}"],
                "acceptance": [f"a{i}"], "artifacts": [],
                "depends_on": [] if i == 1 else [i - 1],
                "next_task": i + 1 if i < n else None,
            }, separators=(",", ":")) + "\n")


def events(tasks_dir: Path):
    f = tasks_dir / "COMPLETIONS.jsonl"
    return ([json.loads(l) for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]
            if f.exists() else [])


def main() -> int:
    from aiosh_mcp.server import aios_task

    tmp = Path(tempfile.mkdtemp(prefix="task-mcp-smoke-"))
    tasks_dir = tmp / "tasks"; tasks_dir.mkdir()
    home = tmp / "home"; home.mkdir()
    make_ledger(tasks_dir / "MASTER_TASK_LEDGER.jsonl", n=4)
    state_path = tasks_dir / "TASK_STATE.json"
    state_path.write_text(json.dumps({
        "schema_version": 2, "ledger": "MASTER_TASK_LEDGER.jsonl",
        "total_tasks": 4, "next_task": 1, "completed": [], "blocked": [],
        "skipped": [], "last_completed_at": None, "last_event_seq": 0,
        "rule": "Execute ONLY next_task.",
    }), encoding="utf-8")
    os.environ["AIOSH_TASKS_DIR"] = str(tasks_dir)
    os.environ["AIOSH_HOME"] = str(home)

    g = subprocess.run([str(BIN), "grant", "create", "--to", "pysmoke",
                        "--tools", "aios.task", "--ttl", "600"],
                       capture_output=True, text=True)
    grant_id = json.loads(g.stdout)["data"]["grant_id"]

    def check(label, ok, detail=""):
        print(f"{PASS if ok else FAIL} {label}")
        if not ok:
            print("   ", detail)
            return False
        return True

    # P1
    r = aios_task(action="status")
    if not check("P1 status envelope", r.get("ok") and r["data"]["next_task"] == 1
                 and r.get("audit_id", 0) > 0, r): return 1

    # P2
    before_ev = len(events(tasks_dir))
    r = aios_task(action="done", task_id=1, note="py smoke",
                  evidence=["e.md"], grant_id=grant_id)
    ev = events(tasks_dir)
    stub = tasks_dir / "evidence" / "T-00001-completion.md"
    ok = (r.get("ok") and len(ev) == before_ev + 1 and stub.exists()
          and ev[-1]["note"] == "py smoke")
    if not check("P2 done: pointer+event+stub", ok, (r, ev)): return 1

    # P3
    r = aios_task(action="frobnicate")
    ok = r.get("ok") is False and "unknown action" in r.get("error", "")
    if not check("P3 unknown action refused", ok, r): return 1

    # P4
    r = aios_task(action="done", task_id=2, note="", grant_id=grant_id)
    ok = r.get("ok") is False and "'note'" in r.get("error", "")
    if not check("P4 empty note refused", ok, r): return 1

    # P5
    r = aios_task(action="done", task_id=2, note="x" * (MAX_NOTE + 1),
                  grant_id=grant_id)
    ok = r.get("ok") is False and "exceeds" in r.get("error", "")
    if not check("P5 oversized note refused", ok, r): return 1

    # P6
    before = state_path.read_text(encoding="utf-8")
    r = aios_task(action="rebuild")
    ok = (r.get("ok") is False and r.get("gate") == "pep"
          and r.get("audit_id", 0) > 0
          and state_path.read_text(encoding="utf-8") == before)
    if not check("P6 no-grant mutation refused at gate", ok, r): return 1

    # T-02902: invariant I-2 (redeem-before-act) makes grants single-shot;
    # the P2 grant was consumed by its successful `done`, so every later
    # mutation must mint a FRESH grant — reusing the consumed one is
    # (correctly) refused at the PEP gate before the tool body runs.
    def _fresh_grant() -> str:
        g = subprocess.run([str(BIN), "grant", "create", "--to", "pysmoke",
                            "--tools", "aios.task", "--ttl", "600"],
                           capture_output=True, text=True)
        return json.loads(g.stdout)["data"]["grant_id"]

    # P7
    before = state_path.read_text(encoding="utf-8")
    n_ev = len(events(tasks_dir))
    r = aios_task(action="done", task_id=4, note="jump", grant_id=_fresh_grant())
    ok = (r.get("ok") is False and "NO-SKIP" in r.get("error", "")
          and state_path.read_text(encoding="utf-8") == before
          and len(events(tasks_dir)) == n_ev)
    if not check("P7 NO-SKIP refusal, zero change", ok, r): return 1

    # P8 — skip then rebuild through the SAME surface
    # (each mutation consumes its own single-shot grant — T-02902/I-2)
    r = aios_task(action="done", task_id=2, note="b", grant_id=_fresh_grant())
    ok0 = r.get("ok") and r.get("next_task") == 3      # mutation envelope: top-level fields
    r = aios_task(action="skip", task_id=3, reason="scope", grant_id=_fresh_grant())
    ok0 = ok0 and r.get("ok") and r.get("next_task") == 4
    state_path.write_text("{}", encoding="utf-8")
    r = aios_task(action="rebuild", grant_id=_fresh_grant())
    d = r.get("data", {})
    ok = ok0 and r.get("ok") and d.get("next_task") == 4 \
         and d.get("skipped") == [3] and d.get("completed") == [1, 2]
    if not check("P8 rebuild replays skip pointer (D4)", ok, (ok0, r)): return 1

    print()
    print("PASS: task mcp wire smoke (P1..P8)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
