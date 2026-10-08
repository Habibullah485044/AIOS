#!/usr/bin/env python3
"""Task Ledger Control CLI surface — wire smoke (T-00035).

Drives the REAL `aiosh` binary against a fully isolated sandbox
(temp `AIOSH_TASKS_DIR` + temp `AIOSH_HOME`), asserting observable
behavior only: stdout envelopes, exit codes, ledger files on disk,
event-log contents, and audit-ring rows.

Coverage (spec T-00032 §4 matrix):
  C1  valid read: status envelope + exit 0
  C2  valid mutation: done advances pointer, event appended, evidence
      stub exists, audit row written (fail-open honest trail)
  C3  invalid: empty --note refused, zero state change
  C4  invalid: missing value at end refused ("missing value")
  C5  boundary: oversized note (>4096) refused
  C6  boundary: task_id "0" refused
  C7  primary failure mode: NO-SKIP refusal — isError envelope,
      byte-identical state file, no new events
  C8  delimiter: `--reason -- --weird` stores the literal dash-leading
      reason in state + event verbatim
  C9  help subcommand exits 0 without touching the ledger
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
REPO = HERE.parents[2]                 # code/aiosh-cli/tests -> repo root
def _rust_bin(name: str) -> Path:
    """Resolve a debug binary, tolerating the Windows .exe suffix (T-02902)."""
    base = REPO / "code" / "aiosh-rust" / "target" / "debug" / name
    exe = base.with_name(base.name + ".exe")
    return exe if os.name == "nt" and exe.exists() else base

BIN = _rust_bin("aiosh")

PASS, FAIL = "[✓]", "[✗]"
MAX_NOTE = 4096


def make_ledger(path: Path, n: int = 3) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for i in range(1, n + 1):
            f.write(json.dumps({
                "id": i, "title": f"task {i}", "phase": "Phase 0 — Test",
                "status": "pending", "goal": f"g{i}", "instructions": [f"s{i}"],
                "acceptance": [f"a{i}"], "artifacts": [],
                "depends_on": [] if i == 1 else [i - 1],
                "next_task": i + 1 if i < n else None,
            }, separators=(",", ":")) + "\n")


def run(env, *args):
    """Refusal envelopes go to STDERR (err_out convention); success to stdout."""
    p = subprocess.run([str(BIN), "task", *args],
                       capture_output=True, text=True, env=env, timeout=60)
    for stream in (p.stdout, p.stderr):
        s = stream.strip()
        if s:
            try:
                return p.returncode, json.loads(s)
            except json.JSONDecodeError:
                pass
    return p.returncode, {"_stdout": p.stdout, "_stderr": p.stderr}


def events(tasks_dir: Path):
    f = tasks_dir / "COMPLETIONS.jsonl"
    if not f.exists():
        return []
    return [json.loads(l) for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]


def main() -> int:
    if not BIN.exists():
        print(f"{FAIL} aiosh binary missing: {BIN} (run cargo build)")
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="task-cli-smoke-"))
    tasks_dir = tmp / "tasks"; tasks_dir.mkdir()
    home = tmp / "home"; home.mkdir()
    make_ledger(tasks_dir / "MASTER_TASK_LEDGER.jsonl", n=3)
    state_path = tasks_dir / "TASK_STATE.json"
    state_path.write_text(json.dumps({
        "schema_version": 2, "ledger": "MASTER_TASK_LEDGER.jsonl",
        "total_tasks": 3, "next_task": 1, "completed": [], "blocked": [],
        "skipped": [], "last_completed_at": None, "last_event_seq": 0,
        "rule": "Execute ONLY next_task.",
    }), encoding="utf-8")
    env = {**os.environ, "AIOSH_TASKS_DIR": str(tasks_dir), "AIOSH_HOME": str(home)}

    def check(label, ok, detail=""):
        print(f"{PASS if ok else FAIL} {label}")
        if not ok:
            print("   ", detail)
            return False
        return True

    # C1 — valid read
    code, d = run(env, "status")
    ok = code == 0 and d["ok"] is True and d["data"]["next_task"] == 1 \
         and d["subcommand"] == "task status"
    if not check("C1 status envelope + exit 0", ok, d): return 1

    # C2 — valid mutation observables
    code, d = run(env, "done", "1", "--note", "cli smoke",
                  "--evidence", "docs/x.md")
    ev = events(tasks_dir)
    stub = tasks_dir / "evidence" / "T-00001-completion.md"
    tail = subprocess.run([str(BIN), "audit", "tail", "1"], env=env,
                          capture_output=True, text=True)
    tail_row = json.loads(tail.stdout)["data"]["rows"][0]
    ok = (code == 0 and d["ok"] is True and len(ev) == 1
          and ev[0]["note"] == "cli smoke" and stub.exists()
          and tail_row["tool"] == "task.ledger" and tail_row["outcome"] == "ok")
    if not check("C2 done: pointer+event+stub+audit row", ok, (d, ev)): return 1

    # C3 — empty note refused, zero change
    before = state_path.read_text(encoding="utf-8")
    n_ev = len(events(tasks_dir))
    code, d = run(env, "done", "2", "--note", "")
    ok = (code == 1 and d["ok"] is False and "'note'" in d.get("error", "")
          and before == state_path.read_text(encoding="utf-8")
          and len(events(tasks_dir)) == n_ev)
    if not check("C3 empty --note refused, zero state change", ok, d): return 1

    # C4 — missing value at end
    code, d = run(env, "skip", "2", "--reason")
    ok = code == 1 and "missing value for '--reason'" in d.get("error", "")
    if not check("C4 missing option value refused", ok, d): return 1

    # C5 — boundary: oversized note
    code, d = run(env, "done", "2", "--note", "x" * (MAX_NOTE + 1))
    ok = code == 1 and "exceeds" in d.get("error", "")
    if not check("C5 note >4096 refused", ok, d): return 1

    # C6 — boundary: task_id below minimum
    code, d = run(env, "done", "0", "--note", "x")
    ok = code == 1 and "must be >= 1" in d.get("error", "")
    if not check("C6 task_id 0 refused", ok, d): return 1

    # C7 — primary failure mode: NO-SKIP, zero change, audited refusal
    before = state_path.read_text(encoding="utf-8")
    n_ev = len(events(tasks_dir))
    code, d = run(env, "done", "3", "--note", "jump")
    after = state_path.read_text(encoding="utf-8")
    n_after = len(events(tasks_dir))
    tail = subprocess.run([str(BIN), "audit", "tail", "1"], env=env,
                          capture_output=True, text=True)
    tail_row = json.loads(tail.stdout)["data"]["rows"][0]
    ok = (code == 1 and d["ok"] is False and "NO-SKIP" in d.get("error", "")
          and before == after and n_ev == n_after
          and tail_row["tool"] == "task.ledger" and tail_row["outcome"] == "refused")
    if not check("C7 NO-SKIP: refused, unchanged, audited", ok, (d, tail_row)): return 1

    # C8 — delimiter passthrough of dash-leading reason
    code, d = run(env, "skip", "2", "--reason", "--", "--weird-reason")
    ev = events(tasks_dir)
    ok = (code == 0 and d["ok"] is True
          and d["data"]["reason"] == "--weird-reason"
          and ev[-1]["note"] == "--weird-reason")
    if not check("C8 '--' stores literal dash-leading reason", ok, (d, ev[-1])): return 1

    # C9 — help exits 0, ledger untouched
    n_ev = len(events(tasks_dir))
    code, _ = run(env, "help")
    ok = code == 0 and len(events(tasks_dir)) == n_ev
    if not check("C9 help exits 0, no side effects", ok): return 1

    print()
    print("PASS: task cli wire smoke (C1..C9)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
