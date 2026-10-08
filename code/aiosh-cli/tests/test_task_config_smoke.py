#!/usr/bin/env python3
"""Task Ledger Control configuration — smoke (T-00055).

Drives the REAL `aiosh` binary against an isolated sandbox, asserting
the AIOSH_LEDGER_* env-config contract (spec T-00052):

  K1 config subcommand: all six knobs present, source=default
  K2 env override: value + source flip to "env"
  K3 override is APPLIED: MAX_TEXT=20... wait, floor is 64; use 8192
     -> a 5000-char note that fails at default now passes validation
        (and completes against a scratch ledger)
  K4 invalid value: loud error NAMING the variable, exit 1, audited
  K5 range violation: below-floor value refused naming the floor
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


def make_ledger(path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps({
            "id": 1, "title": "t1", "phase": "P", "status": "pending",
            "goal": "g", "instructions": ["s"], "acceptance": ["a"],
            "artifacts": [], "depends_on": [], "next_task": 2,
        }, separators=(",", ":")) + "\n")
    Path(str(path).replace("MASTER_TASK_LEDGER.jsonl", "TASK_STATE.json")).write_text(
        json.dumps({
            "schema_version": 2, "ledger": "MASTER_TASK_LEDGER.jsonl",
            "total_tasks": 1, "next_task": 1, "completed": [], "blocked": [],
            "skipped": [], "last_completed_at": None, "last_event_seq": 0,
            "rule": "r",
        }), encoding="utf-8")


def run(env, *args):
    p = subprocess.run([str(BIN), "task", *args], capture_output=True,
                       text=True, env=env, timeout=60)
    for stream in (p.stdout, p.stderr):
        s = stream.strip()
        if s:
            try:
                return p.returncode, json.loads(s)
            except json.JSONDecodeError:
                pass
    return p.returncode, {}


def main() -> int:
    if not BIN.exists():
        print(f"{FAIL} binary missing: {BIN}")
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="task-config-smoke-"))
    tasks_dir = tmp / "tasks"; tasks_dir.mkdir()
    home = tmp / "home"; home.mkdir()
    make_ledger(tasks_dir / "MASTER_TASK_LEDGER.jsonl")
    base = {**os.environ, "AIOSH_TASKS_DIR": str(tasks_dir), "AIOSH_HOME": str(home)}
    for k in list(base):
        if k.startswith("AIOSH_LEDGER_"):
            base.pop(k)

    def check(label, ok, detail=""):
        print(f"{PASS if ok else FAIL} {label}")
        if not ok:
            print("   ", detail)
            return False
        return True

    # K1 — defaults + sources
    code, d = run(base, "config")
    data = d.get("data", {})
    want = {"lock_timeout_secs", "max_ledger_bytes", "max_events_bytes",
            "max_state_bytes", "max_text", "max_evidence_items"}
    ok = (code == 0 and d["ok"] and want <= set(data)
          and all(data[k]["source"] == "default" for k in want))
    if not check("K1 six knobs, source=default", ok, d): return 1

    # K2 — override flips value+source
    env = {**base, "AIOSH_LEDGER_MAX_TEXT": "8192"}
    code, d = run(env, "config")
    mt = d["data"]["max_text"]
    ok = mt == {"value": 8192, "source": "env"}
    if not check("K2 override value+source=env", ok, d): return 1

    # K3 — override APPLIED: 5000-char note refused by default, accepted at 8192
    long = "x" * 5000
    code, d = run(base, "done", "1", "--note", long)
    refused_default = code == 1 and "exceeds" in d.get("error", "")
    code, d = run(env, "done", "1", "--note", long)
    accepted = code == 0 and d.get("ok") is True
    ev = [json.loads(l) for l in (tasks_dir / "COMPLETIONS.jsonl").read_text().splitlines() if l.strip()]
    ok = refused_default and accepted and len(ev[-1]["note"]) == 5000
    if not check("K3 cap override applied end-to-end", ok, (refused_default, d)): return 1

    # K4 — invalid value: named, exit 1, audited
    env_bad = {**base, "AIOSH_LEDGER_LOCK_TIMEOUT_SECS": "soon"}
    code, d = run(env_bad, "status")
    tail = subprocess.run([str(BIN), "audit", "tail", "1"], env=env_bad,
                          capture_output=True, text=True)
    row = json.loads(tail.stdout)["data"]["rows"][0]
    ok = (code == 1 and "invalid AIOSH_LEDGER_LOCK_TIMEOUT_SECS='soon'" in d.get("error", "")
          and row["outcome"] == "refused")
    if not check("K4 invalid value named + audited", ok, (d, row)): return 1

    # K5 — range floor
    env_lo = {**base, "AIOSH_LEDGER_MAX_TEXT": "10"}
    code, d = run(env_lo, "config")
    ok = code == 1 and "must be >= 64" in d.get("error", "")
    if not check("K5 below-floor refused (must be >= 64)", ok, d): return 1

    print()
    print("PASS: task config smoke (K1..K5)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
