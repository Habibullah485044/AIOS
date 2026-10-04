"""Ledger feature-block insertion — unit tests.

Standalone, repo smoke style (PASS/FAIL markers, non-zero exit on
failure). Every case runs `tools/ledger_insert_block.py` as a subprocess
against a temp tasks dir (--tasks-dir); the real docs/tasks is never
touched.

Coverage:
  I1 dry-run reports the plan and changes nothing
  I2 insert: block lands after N, ids contiguous, history lines
     byte-identical, later tasks renumbered (incl. own T-NNNNN tokens),
     standing rules applied, state rebuilt, pointer unchanged, amendment logged
  I3 inserting the same feature twice is refused
  I4 inserting into history (before a completed task) is refused
  I5 refresh-rules replaces changed rule text without duplicates; 2nd run is a no-op
  I6 generate_master_tasks.py refuses to overwrite an existing ledger
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE / "ledger_insert_block.py"
PHASE = "Phase 2 — Test Phase"
PASS, FAIL = "[+]", "[-]"
TYPES = ["Research", "Security Review", "Verification & Evidence"]


def make_fixture(d: Path, n: int = 12, done: int = 2) -> None:
    with open(d / "MASTER_TASK_LEDGER.jsonl", "w", encoding="utf-8") as f:
        for i in range(1, n + 1):
            t = TYPES[(i - 1) % len(TYPES)]
            f.write(json.dumps({
                "id": i, "title": f"{PHASE} / Epic / comp: {t}", "phase": PHASE,
                "status": "done" if i <= done else "pending",
                "goal": f"goal {i}",
                "instructions": [f"write docs/tasks/evidence/T-{i:05d}-x.md", "close out"],
                "acceptance": [f"accept {i}"],
                "artifacts": [f"docs/tasks/evidence/T-{i:05d}-x.md"],
                "depends_on": [] if i == 1 else [i - 1],
                "next_task": i + 1 if i < n else None,
            }, ensure_ascii=False, separators=(",", ":")) + "\n")
    with open(d / "COMPLETIONS.jsonl", "w", encoding="utf-8") as f:
        for i in range(1, done + 1):
            f.write(json.dumps({"seq": i, "ts": "2026-01-01T00:00:00Z",
                                "event": "completed", "task_id": i,
                                "note": "", "evidence": []}) + "\n")
    (d / "TASK_STATE.json").write_text(json.dumps({
        "schema_version": 2, "ledger": "MASTER_TASK_LEDGER.jsonl",
        "total_tasks": n, "next_task": done + 1,
        "completed": list(range(1, done + 1)), "blocked": [], "skipped": [],
        "last_completed_at": "2026-01-01T00:00:00Z", "last_event_seq": done,
        "rule": "x"}), encoding="utf-8")
    (d / "MASTER_TASK_LEDGER.md").write_text(
        f"# MASTER TASK LEDGER — {n:,} sequential tasks\n\n| Phase | Task range |\n|---|---|\n"
        f"| {PHASE} | T-00001 .. T-{n:05d} |\n", encoding="utf-8")


def make_spec(d: Path, rule_text: str = "[TST] check restraint") -> Path:
    spec = {
        "feature_id": "test-feature", "epic": "Test Feature", "phase": PHASE,
        "kickoff": {"title": "kickoff", "goal": "g", "instructions": ["k T-{task_id:05d}"],
                    "acceptance": ["a"]},
        "components": ["alpha"],
        "pre": ["read PLAN for {component}"], "post": ["log T-{task_id:05d}"],
        "closing": {"title": "closing", "goal": "g", "instructions": ["c"], "acceptance": ["a"]},
        "standing_rules": [{"applies_to_title_suffix": ": Security Review",
                            "instruction": rule_text}],
    }
    p = d / "spec.json"
    p.write_text(json.dumps(spec), encoding="utf-8")
    return p


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(TOOL), *args],
                          capture_output=True, text=True, encoding="utf-8")


def ledger(d: Path) -> list[dict]:
    return [json.loads(l) for l in open(d / "MASTER_TASK_LEDGER.jsonl", encoding="utf-8") if l.strip()]


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"{PASS if ok else FAIL} {name}" + (f" — {detail}" if detail and not ok else ""))
    return ok


def main() -> int:
    results = []
    d = Path(tempfile.mkdtemp(prefix="ledger-insert-"))
    make_fixture(d)
    spec = make_spec(d)
    before = (d / "MASTER_TASK_LEDGER.jsonl").read_bytes()
    raw_before = before.splitlines(keepends=True)

    # I1
    r = run("insert", "--spec", str(spec), "--after", "3", "--tasks-dir", str(d), "--dry-run")
    results.append(check("I1 dry-run is read-only",
                         r.returncode == 0 and (d / "MASTER_TASK_LEDGER.jsonl").read_bytes() == before
                         and json.loads(r.stdout)["block_size"] == 12, r.stderr or r.stdout))

    # I2
    r = run("insert", "--spec", str(spec), "--after", "3", "--tasks-dir", str(d))
    recs = ledger(d)
    raw_after = (d / "MASTER_TASK_LEDGER.jsonl").read_bytes().splitlines(keepends=True)
    state = json.loads((d / "TASK_STATE.json").read_text(encoding="utf-8"))
    old4 = recs[3 + 12]  # original task 4 -> 16
    sec = [t for t in recs[15:] if t["title"].endswith(": Security Review")]
    amend = (d / "LEDGER_AMENDMENTS.jsonl").read_text(encoding="utf-8")
    ok = (r.returncode == 0
          and [t["id"] for t in recs] == list(range(1, 25))
          and raw_after[:3] == raw_before[:3]
          and recs[3]["title"] == "kickoff" and recs[3]["instructions"] == ["k T-00004"]
          and recs[14]["title"] == "closing"
          and recs[4]["instructions"][0] == "read PLAN for alpha"
          and recs[4]["instructions"][-1] == "log T-00005"
          and old4["goal"] == "goal 4" and old4["id"] == 16
          and old4["artifacts"] == ["docs/tasks/evidence/T-00016-x.md"]
          and all("[TST] check restraint" in t["instructions"] for t in sec)
          and all(t["instructions"][-1] == "close out" for t in sec)
          and not any("[TST]" in s for t in recs[:15] for s in t["instructions"])
          and state["total_tasks"] == 24 and state["next_task"] == 3
          and '"feature_id":"test-feature"' in amend
          and "24 sequential tasks" in (d / "MASTER_TASK_LEDGER.md").read_text(encoding="utf-8")
          and "T-00001 .. T-00024" in (d / "MASTER_TASK_LEDGER.md").read_text(encoding="utf-8"))
    results.append(check("I2 insert renumbers safely and applies rules", ok, r.stderr or r.stdout))

    # I3
    r = run("insert", "--spec", str(spec), "--after", "20", "--tasks-dir", str(d))
    results.append(check("I3 duplicate feature refused",
                         r.returncode != 0 and "already inserted" in (r.stderr + r.stdout)))

    # I4
    d2 = Path(tempfile.mkdtemp(prefix="ledger-insert-hist-"))
    make_fixture(d2, done=5)
    r = run("insert", "--spec", str(make_spec(d2)), "--after", "2", "--tasks-dir", str(d2))
    results.append(check("I4 insertion into history refused",
                         r.returncode != 0 and "History is never renumbered" in (r.stderr + r.stdout)))

    # I5
    spec2 = make_spec(d, rule_text="[TST] check restraint v2")
    r1 = run("refresh-rules", "--spec", str(spec2), "--tasks-dir", str(d))
    recs = ledger(d)
    sec = [t for t in recs[15:] if t["title"].endswith(": Security Review")]
    r2 = run("refresh-rules", "--spec", str(spec2), "--tasks-dir", str(d))
    ok = (r1.returncode == 0 and json.loads(r1.stdout)["tasks_updated"] == len(sec)
          and all(sum(s.startswith("[TST]") for s in t["instructions"]) == 1
                  and "[TST] check restraint v2" in t["instructions"] for t in sec)
          and r2.returncode == 0 and json.loads(r2.stdout)["tasks_updated"] == 0)
    results.append(check("I5 refresh-rules replaces and is idempotent", ok, r1.stderr + r2.stderr))

    # I6 (real repo ledger exists -> generator must refuse; it never writes)
    r = subprocess.run([sys.executable, str(HERE / "generate_master_tasks.py")],
                       capture_output=True, text=True, encoding="utf-8")
    results.append(check("I6 generator refuses overwrite",
                         r.returncode == 2 and "refusing" in r.stdout, r.stdout + r.stderr))

    if all(results):
        print(f"PASS: ledger_insert_block ({len(results)}/{len(results)})")
        return 0
    print("FAIL: ledger_insert_block")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
