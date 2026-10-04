#!/usr/bin/env python3
"""Insert a feature block into the live master ledger (and keep it alive).

Why this exists: the master ledger was generated once (10,000 tasks) and
is executed strictly in order. New features must land *inside* that
sequence without hand-editing thousands of lines and without touching
history. This tool does it mechanically and safely:

  insert   python3 tools/ledger_insert_block.py insert \
               --spec docs/proof-of-restraint/ledger_block.json --after 2830
           - builds the block (kickoff + components x REP 10 steps + closing)
             using the SAME templates as tools/generate_master_tasks.py
           - renumbers every later (pending) task by +K, including the
             T-NNNNN tokens inside its own text/artifact paths
           - appends the spec's standing rules to matching future tasks
           - relinks depends_on / next_task, rewrites atomically, rebuilds
             TASK_STATE.json from the event log, updates the index phase map,
             and records the amendment in docs/tasks/LEDGER_AMENDMENTS.jsonl

  refresh-rules  python3 tools/ledger_insert_block.py refresh-rules \
               --spec docs/proof-of-restraint/ledger_block.json
           - re-applies the CURRENT standing rules to every pending task
             after the block (old rule lines with the same tag are replaced).
             Run this whenever the feature's PLAN changes its standing rules;
             it is idempotent and never touches done/blocked/skipped tasks.

Safety invariants (refuses otherwise):
  - ledger invariants hold before and after (contiguous ids, linked chain)
  - every task after the insertion point is pending and not in the
    completed/blocked/skipped sets (history is never renumbered)
  - a feature id is inserted at most once
  - lines for tasks <= --after are written back byte-for-byte unchanged
  - the completion event log (COMPLETIONS.jsonl) is never modified
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import task_ledger as tl  # noqa: E402
from generate_master_tasks import TASK_TYPES, build_component_tasks  # noqa: E402

AMENDMENTS = "LEDGER_AMENDMENTS.jsonl"
_PHASE_ROW = re.compile(r"^\| (Phase \d+ — [^|]+?) \| T-(\d{5}) \.\. T-(\d{5}) \|$", re.M)
_COUNT_HDR = re.compile(r"— [\d,]+ sequential tasks")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dump(rec: dict[str, Any]) -> str:
    return json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n"


def _paths(tasks_dir: str) -> dict[str, str]:
    return {
        "ledger": os.path.join(tasks_dir, "MASTER_TASK_LEDGER.jsonl"),
        "state": os.path.join(tasks_dir, "TASK_STATE.json"),
        "events": os.path.join(tasks_dir, "COMPLETIONS.jsonl"),
        "lock": os.path.join(tasks_dir, ".TASK_STATE.lock"),
        "index": os.path.join(tasks_dir, "MASTER_TASK_LEDGER.md"),
        "amend": os.path.join(tasks_dir, AMENDMENTS),
    }


def _read_ledger(path: str) -> tuple[list[str], list[dict[str, Any]]]:
    raw, recs = [], []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            raw.append(line if line.endswith("\n") else line + "\n")
            recs.append(json.loads(line))
    return raw, recs


def _read_amendments(path: str) -> list[dict[str, Any]]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def _shift_text(value: Any, old: int, new: int) -> Any:
    """Rewrite this task's own T-NNNNN token (strings, recursively)."""
    a, b = f"T-{old:05d}", f"T-{new:05d}"
    if isinstance(value, str):
        return value.replace(a, b)
    if isinstance(value, list):
        return [_shift_text(v, old, new) for v in value]
    return value


def _apply_rules(rec: dict[str, Any], rules: list[dict[str, str]], tag: str) -> bool:
    """Replace this feature's tagged rule lines with the current rules.
    Rules go just before the final instruction (the close-out step)."""
    ins = [s for s in rec["instructions"] if not s.startswith(tag)]
    add = [r["instruction"] for r in rules
           if rec["title"].endswith(r["applies_to_title_suffix"])]
    if add:
        pos = max(len(ins) - 1, 0)
        ins = ins[:pos] + add + ins[pos:]
    if ins != rec["instructions"]:
        rec["instructions"] = ins
        return True
    return False


def _rule_tag(spec: dict[str, Any]) -> str:
    tags = {r["instruction"].split("]", 1)[0] + "]" for r in spec.get("standing_rules", [])}
    if len(tags) > 1:
        raise SystemExit(f"standing_rules must share one [TAG] prefix, got {sorted(tags)}")
    return tags.pop() if tags else ""


def _custom(tid: int, phase: str, block: dict[str, Any]) -> dict[str, Any]:
    ctx = {"task_id": tid}
    return {
        "id": tid, "title": block["title"], "phase": phase, "status": "pending",
        "goal": block["goal"],
        "instructions": [s.format(**ctx) for s in block["instructions"]],
        "acceptance": [s.format(**ctx) for s in block["acceptance"]],
        "artifacts": [f"docs/tasks/evidence/T-{tid:05d}.md"],
    }


def build_block(spec: dict[str, Any], start: int) -> list[dict[str, Any]]:
    phase = spec["phase"]
    out = [_custom(start, phase, spec["kickoff"])]
    out += build_component_tasks(phase, spec["epic"], spec["components"], start + 1,
                                 pre=spec.get("pre", ()), post=spec.get("post", ()),
                                 focus=spec.get("focus"))
    out.append(_custom(start + len(out), phase, spec["closing"]))
    return out


def _relink(recs: list[dict[str, Any]]) -> None:
    for i, r in enumerate(recs):
        r["depends_on"] = [recs[i - 1]["id"]] if i > 0 else []
        r["next_task"] = recs[i + 1]["id"] if i + 1 < len(recs) else None


def _write_atomic(path: str, lines: list[str]) -> None:
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        f.writelines(lines)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _update_index(index_path: str, recs: list[dict[str, Any]]) -> None:
    if not os.path.exists(index_path):
        return
    ranges: dict[str, list[int]] = {}
    for r in recs:
        ranges.setdefault(r["phase"], [r["id"], r["id"]])[1] = r["id"]
    with open(index_path, encoding="utf-8") as f:
        text = f.read()

    def row(m: re.Match) -> str:
        lo, hi = ranges.get(m.group(1), [int(m.group(2)), int(m.group(3))])
        return f"| {m.group(1)} | T-{lo:05d} .. T-{hi:05d} |"

    text = _PHASE_ROW.sub(row, text)
    text = _COUNT_HDR.sub(f"— {len(recs):,} sequential tasks", text, count=1)
    with open(index_path, "w", encoding="utf-8") as f:
        f.write(text)


def _check(ledger: str) -> None:
    inv = tl.assert_ledger_invariants(ledger)
    if not inv.get("ok"):
        raise SystemExit(f"ledger invariant violation: {inv}")


def cmd_insert(spec_path: str, after: int, tasks_dir: str, dry_run: bool) -> int:
    p = _paths(tasks_dir)
    with open(spec_path, encoding="utf-8") as f:
        spec = json.load(f)
    tag = _rule_tag(spec)
    with tl.acquire_lock(p["lock"]):
        _check(p["ledger"])
        if any(a.get("feature_id") == spec["feature_id"] for a in _read_amendments(p["amend"])):
            raise SystemExit(f"feature {spec['feature_id']!r} already inserted "
                             f"(see {AMENDMENTS}); use refresh-rules to update it")
        raw, recs = _read_ledger(p["ledger"])
        total = len(recs)
        if not (0 <= after <= total):
            raise SystemExit(f"--after {after} outside 0..{total}")
        state = tl.load_state(p["state"])
        history = set(state.get("completed", [])) | set(state.get("blocked", [])) \
            | set(state.get("skipped", []))
        bad = [r["id"] for r in recs[after:]
               if r.get("status") != "pending" or r["id"] in history]
        if bad:
            raise SystemExit(f"refusing: tasks after T-{after:05d} are not all pending "
                             f"(first offenders: {bad[:5]}). History is never renumbered.")
        marker = f"/ {spec['epic']} /"
        if any(marker in r["title"] for r in recs):
            raise SystemExit(f"epic {spec['epic']!r} already present in ledger titles")

        block = build_block(spec, after + 1)
        k = len(block)
        tail = []
        applied = 0
        for r in recs[after:]:
            old = r["id"]
            new = old + k
            r = {key: _shift_text(v, old, new) if key in
                 ("title", "goal", "instructions", "acceptance", "artifacts") else v
                 for key, v in r.items()}
            r["id"] = new
            if tag and _apply_rules(r, spec.get("standing_rules", []), tag):
                applied += 1
            tail.append(r)

        merged = recs[:after] + block + tail
        _relink(merged)
        # Keep history lines byte-identical except the boundary task whose
        # next_task link is unchanged anyway (after -> after+1).
        out_lines = raw[:after] + [_dump(r) for r in block + tail]
        if after > 0 and json.loads(raw[after - 1])["next_task"] != after + 1:
            out_lines[after - 1] = _dump(merged[after - 1])

        summary = {
            "feature_id": spec["feature_id"], "after": after,
            "inserted": [after + 1, after + k], "block_size": k,
            "renumbered": len(tail), "standing_rules_applied": applied,
            "total_before": total, "total_after": len(merged),
        }
        if dry_run:
            print(json.dumps({"dry_run": True, **summary}, indent=2))
            return 0

        _write_atomic(p["ledger"], out_lines)
        _check(p["ledger"])
        new_state = tl.rebuild_state(p["events"], p["ledger"], p["state"])
        _update_index(p["index"], merged)
        with open(p["amend"], "a", encoding="utf-8") as f:
            f.write(_dump({"ts": _now(), "action": "insert", "spec": spec_path.replace("\\", "/"),
                           **summary}))
        print(json.dumps({**summary, "next_task": new_state["next_task"],
                          "total_tasks": new_state["total_tasks"]}, indent=2))
    return 0


def cmd_refresh(spec_path: str, tasks_dir: str, dry_run: bool) -> int:
    p = _paths(tasks_dir)
    with open(spec_path, encoding="utf-8") as f:
        spec = json.load(f)
    tag = _rule_tag(spec)
    if not tag:
        raise SystemExit("spec has no standing_rules")
    with tl.acquire_lock(p["lock"]):
        _check(p["ledger"])
        ins = [a for a in _read_amendments(p["amend"])
               if a.get("feature_id") == spec["feature_id"] and a.get("action") == "insert"]
        if not ins:
            raise SystemExit(f"feature {spec['feature_id']!r} was never inserted")
        block_end = ins[-1]["inserted"][1]
        raw, recs = _read_ledger(p["ledger"])
        state = tl.load_state(p["state"])
        history = set(state.get("completed", [])) | set(state.get("blocked", [])) \
            | set(state.get("skipped", []))
        changed = 0
        out = list(raw)
        for i, r in enumerate(recs):
            if r["id"] <= block_end or r["id"] in history or r.get("status") != "pending":
                continue
            if _apply_rules(r, spec["standing_rules"], tag):
                out[i] = _dump(r)
                changed += 1
        summary = {"feature_id": spec["feature_id"], "action": "refresh-rules",
                   "tasks_updated": changed, "after_block_end": block_end}
        if dry_run or changed == 0:
            print(json.dumps({"dry_run": dry_run, **summary}, indent=2))
            return 0
        _write_atomic(p["ledger"], out)
        _check(p["ledger"])
        with open(p["amend"], "a", encoding="utf-8") as f:
            f.write(_dump({"ts": _now(), "spec": spec_path.replace("\\", "/"), **summary}))
        print(json.dumps(summary, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("insert")
    a.add_argument("--spec", required=True)
    a.add_argument("--after", type=int, required=True)
    r = sub.add_parser("refresh-rules")
    r.add_argument("--spec", required=True)
    for s in (a, r):
        s.add_argument("--tasks-dir", default=tl.DOCS_TASKS)
        s.add_argument("--dry-run", action="store_true")
    ns = ap.parse_args(argv)
    if ns.cmd == "insert":
        return cmd_insert(ns.spec, ns.after, ns.tasks_dir, ns.dry_run)
    return cmd_refresh(ns.spec, ns.tasks_dir, ns.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
