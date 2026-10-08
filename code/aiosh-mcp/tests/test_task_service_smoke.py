#!/usr/bin/env python3
"""Task Ledger Control core service — wire-level smoke (T-00025).

Drives the REAL `aiosh-mcp` binary over stdio JSON-RPC against a fully
isolated sandbox (temp `AIOSH_TASKS_DIR` + temp `AIOSH_HOME`), asserting
observable behavior only: JSON-RPC envelopes, result payloads, ledger
files on disk, and audit-ring rows. Mirrors the repo smoke style
(PASS/FAIL markers, non-zero exit on failure).

Coverage (spec T-00022 §3.3 taxonomy):
  W1  valid read: status returns the live pointer envelope
  W2  valid mutation: done (with grant) advances pointer, appends the
      COMPLETIONS.jsonl event, and creates the evidence stub on disk
  W3  invalid input: unknown enum value -> JSON-RPC -32602
  W4  invalid input: unexpected argument -> JSON-RPC -32602
  W5  boundary: task_id 0 rejected by schema (-32602, minimum: 1)
  W6  boundary: oversized note (> 4096) rejected by schema (-32602)
  W7  primary failure mode: NO-SKIP refusal is an isError result with
      zero state change (no event appended, pointer unchanged)
  W8  gate refusal: consequential action without grant -> gate:"pep",
      honest audit row written (fail-open-with-audit)
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
REPO = HERE.parents[2]                 # code/aiosh-mcp/tests -> repo root
def _rust_bin(name: str) -> Path:
    """Resolve a debug binary, tolerating the Windows .exe suffix (T-02902)."""
    base = REPO / "code" / "aiosh-rust" / "target" / "debug" / name
    exe = base.with_name(base.name + ".exe")
    return exe if os.name == "nt" and exe.exists() else base

BIN = _rust_bin("aiosh-mcp")
CLI = _rust_bin("aiosh")

PASS, FAIL = "[✓]", "[✗]"
MAX_NOTE = 4096


def make_ledger(path: Path, n: int = 3) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for i in range(1, n + 1):
            rec = {
                "id": i, "title": f"task {i}", "phase": "Phase 0 — Test",
                "status": "pending", "goal": f"goal {i}",
                "instructions": [f"step {i}"], "acceptance": [f"accept {i}"],
                "artifacts": [f"evidence/T-{i:05d}.md"],
                "depends_on": [] if i == 1 else [i - 1],
                "next_task": i + 1 if i < n else None,
            }
            f.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")


def rpc(proc, req: dict) -> dict:
    proc.stdin.write(json.dumps(req) + "\n")
    proc.stdin.flush()
    while True:
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("aiosh-mcp closed stdout")
        line = line.strip()
        if line:
            return json.loads(line)


def call(proc, name: str, arguments: dict, rid: int) -> dict:
    return rpc(proc, {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                      "params": {"name": name, "arguments": arguments}})


def result_of(resp: dict) -> dict:
    return json.loads(resp["result"]["content"][0]["text"])


def main() -> int:
    if not BIN.exists():
        print(f"{FAIL} aiosh-mcp binary missing: {BIN} (run cargo build)")
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="task-service-smoke-"))
    tasks_dir = tmp / "tasks"
    tasks_dir.mkdir()
    home = tmp / "home"
    home.mkdir()
    make_ledger(tasks_dir / "MASTER_TASK_LEDGER.jsonl", n=3)
    (tasks_dir / "TASK_STATE.json").write_text(json.dumps({
        "schema_version": 2, "ledger": "MASTER_TASK_LEDGER.jsonl",
        "total_tasks": 3, "next_task": 1, "completed": [], "blocked": [],
        "skipped": [], "last_completed_at": None, "last_event_seq": 0,
        "rule": "Execute ONLY next_task.",
    }), encoding="utf-8")

    env = {**os.environ,
           "AIOSH_TASKS_DIR": str(tasks_dir),
           "AIOSH_HOME": str(home)}

    # PEP grant covering aios.task, minted against the same audit DB.
    g = subprocess.run(
        [str(CLI), "grant", "create", "--to", "smoke", "--tools", "aios.task",
         "--ttl", "600"],
        env=env, capture_output=True, text=True)
    grant_doc = json.loads(g.stdout)
    grant_id = json.dumps(grant_doc)  # fallback scan below
    def find_grant_id(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == "grant_id" and isinstance(v, str):
                    return v
                got = find_grant_id(v)
                if got:
                    return got
        elif isinstance(obj, list):
            for v in obj:
                got = find_grant_id(v)
                if got:
                    return got
        return None
    grant_id = find_grant_id(grant_doc)
    if not grant_id:
        print(f"{FAIL} could not mint grant: {g.stdout} {g.stderr}")
        return 2

    proc = subprocess.Popen([str(BIN)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True, env=env)
    try:
        rpc(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                              "clientInfo": {"name": "task-service-smoke", "version": "1"}}})
        events_path = tasks_dir / "COMPLETIONS.jsonl"

        # W1 — valid read
        r = result_of(call(proc, "aios.task", {"action": "status"}, 10))
        ok = (r.get("ok") is True and r.get("action") == "status"
              and r["data"]["next_task"] == 1 and r["audit_id"] > 0)
        print(f"{PASS if ok else FAIL} W1 status envelope (ok/action/data/audit_id)")
        if not ok: return 1

        # W2 — valid mutation with grant: files + state observables
        r = result_of(call(proc, "aios.task",
                           {"action": "done", "task_id": 1,
                            "note": "smoke done", "evidence": ["docs/x.md"],
                            "grant_id": grant_id}, 11))
        events = [json.loads(l) for l in
                  events_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        stub = tasks_dir / "evidence" / "T-00001-completion.md"
        ok = (r.get("ok") is True and r.get("completed") == 1
              and len(events) == 1 and events[0]["event"] == "completed"
              and stub.exists())
        print(f"{PASS if ok else FAIL} W2 done advances pointer + event + evidence stub")
        if not ok:
            print("   ", r); return 1

        # W3 — invalid enum value -> protocol error
        resp = call(proc, "aios.task", {"action": "frobnicate"}, 12)
        err = resp.get("error", {})
        ok = resp.get("id") == 12 and err.get("code") == -32602 \
             and "unknown action" in err.get("message", "")
        print(f"{PASS if ok else FAIL} W3 unknown action -> -32602")
        if not ok: return 1

        # W4 — unexpected argument -> protocol error
        resp = call(proc, "aios.task", {"action": "status", "extra": 1}, 13)
        ok = resp.get("error", {}).get("code") == -32602
        print(f"{PASS if ok else FAIL} W4 unexpected argument -> -32602")
        if not ok: return 1

        # W5 — boundary: task_id below minimum -> protocol error
        resp = call(proc, "aios.task",
                    {"action": "done", "task_id": 0, "note": "x",
                     "grant_id": grant_id}, 14)
        ok = resp.get("error", {}).get("code") == -32602
        print(f"{PASS if ok else FAIL} W5 task_id 0 -> -32602 (minimum: 1)")
        if not ok: return 1

        # W6 — boundary: oversized note -> protocol error
        resp = call(proc, "aios.task",
                    {"action": "done", "task_id": 2, "note": "x" * (MAX_NOTE + 1),
                     "grant_id": grant_id}, 15)
        ok = resp.get("error", {}).get("code") == -32602
        print(f"{PASS if ok else FAIL} W6 note > 4096 -> -32602")
        if not ok: return 1

        # W7 — primary failure mode: NO-SKIP refusal, zero state change
        before = (tasks_dir / "TASK_STATE.json").read_text(encoding="utf-8")
        n_events_before = len(events_path.read_text(encoding="utf-8").splitlines())
        r = result_of(call(proc, "aios.task",
                           {"action": "done", "task_id": 3, "note": "jump",
                            "grant_id": grant_id}, 16))
        after = (tasks_dir / "TASK_STATE.json").read_text(encoding="utf-8")
        n_events_after = len(events_path.read_text(encoding="utf-8").splitlines())
        resp = call(proc, "aios.task",
                    {"action": "done", "task_id": 3, "note": "jump",
                     "grant_id": grant_id}, 17)
        ok = (r.get("ok") is False and "NO-SKIP" in r.get("error", "")
              and before == after and n_events_before == n_events_after
              and resp["result"]["isError"] is True and r.get("audit_id", 0) > 0)
        print(f"{PASS if ok else FAIL} W7 NO-SKIP refusal: isError, zero state change")
        if not ok:
            print("   ", r); return 1

        # W8 — gate refusal without grant: honest audit row, nothing mutates
        before = (tasks_dir / "TASK_STATE.json").read_text(encoding="utf-8")
        r = result_of(call(proc, "aios.task", {"action": "rebuild"}, 18))
        ok = (r.get("ok") is False and r.get("gate") == "pep"
              and r.get("reason") == "tool 'aios.task' requires explicit PEP grant"
              and r.get("audit_id", 0) > 0 and before == (tasks_dir / "TASK_STATE.json").read_text(encoding="utf-8"))
        print(f"{PASS if ok else FAIL} W8 no-grant mutation refused at PEP gate (audited)")
        if not ok:
            print("   ", r); return 1

    finally:
        if proc.stdin is not None:
            proc.stdin.close()
        proc.wait(timeout=10)

    print()
    print("PASS: task service wire smoke (W1..W8)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
