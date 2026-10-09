#!/usr/bin/env python3
"""Task Ledger Control observability (`metrics`) — unit smoke T-00085.

Contract under test (spec docs/tasks/evidence/T-00082-spec.md): the
read-only `metrics` action composes ONE snapshot with the STABLE
additive-only key set {tasks, audit, config} on every surface, takes NO
task_id, honors AIOSH_LEDGER_* env knobs, and fails LOUDLY (standard
envelope + honest audit row) when inputs or state are hostile.

Surfaces exercised:
  - Rust MCP wire   (code/aiosh-rust/target/debug/aiosh-mcp)
  - Python reference tool function (aiosh_mcp.server.aios_task)
  - Production CLI  (aiosh task metrics)

Cases:
  O1 valid wire:    metrics -> isError:false, stable keys, audit_id > 0
  O2 parity python: same ok envelope + identical top-level key set
  O3 cli:           aiosh task metrics -> ok envelope + same key set,
                    config defaults == LedgerConfig defaults
  O4 negative wire: metrics WITH task_id -> refused (parity with Python)
  O5 negative cli:  `task metrics <id>` -> usage refusal (never silent-ok)
  O6 negative py:   task_id refused PRE-GATE (reference behavior)
  O7 boundaries:    pristine sandbox rows==0/next_task==1; env override
                    max_text=64 visible in config; env below floor ->
                    loud named error
  O8 failure mode:  corrupt TASK_STATE.json -> loud ok:false on BOTH
                    surfaces; CLI still emits one honest audit row
"""

import json
import os
import shutil
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
MCP_BIN = _rust_bin("aiosh-mcp")

PASS, FAIL = "[✓]", "[✗]"
STABLE_KEYS = {"tasks", "audit", "config"}
DEFAULTS = {
    "lock_timeout_secs": 5,
    "max_ledger_bytes": 64 * 1024 * 1024,
    "max_events_bytes": 16 * 1024 * 1024,
    "max_state_bytes": 4 * 1024 * 1024,
    "max_text": 4096,
    "max_evidence_items": 16,
}

RESULTS: list[tuple[str, bool]] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"{PASS if ok else FAIL} {label}" + (f"\n    {detail}" if detail and not ok else ""))
    RESULTS.append((label, ok))


def make_ledger(path: Path, n: int = 3) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for i in range(1, n + 1):
            f.write(json.dumps({
                "id": i, "title": f"t{i}", "phase": "P", "status": "pending",
                "goal": "g", "instructions": ["i"], "acceptance": ["a"],
                "artifacts": [], "depends_on": [] if i == 1 else [i - 1],
                "next_task": i + 1 if i < n else None,
            }, separators=(",", ":")) + "\n")


def pristine_state(path: Path, total: int = 3) -> None:
    path.write_text(json.dumps({
        "schema_version": 2, "ledger": "MASTER_TASK_LEDGER.jsonl",
        "total_tasks": total, "next_task": 1, "completed": [], "blocked": [],
        "skipped": [], "last_completed_at": None, "last_event_seq": 0,
        "rule": "Execute ONLY next_task.",
    }, indent=2) + "\n")


def base_env(tmp: Path) -> dict:
    env = dict(os.environ)
    env["AIOSH_HOME"] = str(tmp / "home")
    env["AIOSH_TASKS_DIR"] = str(tmp / "tasks")
    env["AIOSH_CONSTITUTION"] = str(
        REPO / "mostimportanAIfolder" / "AI_CONSTITUTION.md")
    (tmp / "home").mkdir(parents=True, exist_ok=True)
    (tmp / "tasks").mkdir(parents=True, exist_ok=True)
    make_ledger(tmp / "tasks" / "MASTER_TASK_LEDGER.jsonl")
    pristine_state(tmp / "tasks" / "TASK_STATE.json")
    (tmp / "tasks" / "COMPLETIONS.jsonl").write_text("", encoding="utf-8")
    return env


def rust_wire(env: dict, requests: list[dict]) -> dict[int, dict]:
    payload = "".join(json.dumps(r) + "\n" for r in requests)
    p = subprocess.run([str(MCP_BIN)], input=payload, capture_output=True,
                       text=True, env=env, timeout=30)
    assert p.returncode == 0, f"mcp exited {p.returncode}: {p.stderr[:300]}"
    out: dict[int, dict] = {}
    for line in p.stdout.splitlines():
        if line.strip():
            d = json.loads(line)
            out[d["id"]] = d
    return out


def wire_result(resp: dict) -> dict:
    return json.loads(resp["result"]["content"][0]["text"])


def init_req() -> dict:
    return {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "metrics-smoke", "version": "1"}}}


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="metrics-smoke-"))
    try:
        # ---- O1 valid wire -------------------------------------------------
        env = base_env(tmp / "o1")
        out = rust_wire(env, [init_req(),
                              {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                               "params": {"name": "aios.task",
                                          "arguments": {"action": "metrics"}}}])
        r = wire_result(out[2])
        check("O1 wire ok + stable keys + audited",
              out[2]["result"]["isError"] is False and r.get("ok") is True
              and set(r["data"].keys()) == STABLE_KEYS and r["audit_id"] > 0,
              json.dumps(r)[:300])

        # ---- O2 parity python ----------------------------------------------
        env = base_env(tmp / "o2")
        os.environ.update({k: env[k] for k in
                           ("AIOSH_HOME", "AIOSH_TASKS_DIR", "AIOSH_CONSTITUTION")})
        from aiosh_mcp.server import aios_task
        rp = aios_task(action="metrics")
        check("O2 python parity: ok + identical key set",
              rp.get("ok") is True and set(rp["data"].keys()) == STABLE_KEYS,
              json.dumps(rp, default=str)[:300])
        check("O2b python/wire key-set equality",
              set(rp["data"]) == set(r["data"]))

        # ---- O3 CLI ---------------------------------------------------------
        env = base_env(tmp / "o3")
        p = subprocess.run([str(BIN), "task", "metrics"], capture_output=True,
                           text=True, env=env, timeout=30)
        rc = json.loads(p.stdout)
        cfg = rc.get("data", {}).get("config", {})
        check("O3 cli ok + stable keys + default config",
              rc.get("ok") is True and set(rc["data"].keys()) == STABLE_KEYS
              and cfg == DEFAULTS, p.stdout[:300])

        # ---- O4 negative wire: metrics + task_id ----------------------------
        env = base_env(tmp / "o4")
        out = rust_wire(env, [init_req(),
                              {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                               "params": {"name": "aios.task",
                                          "arguments": {"action": "metrics",
                                                        "task_id": 7}}}])
        r4 = wire_result(out[2])
        refused_wire = (out[2]["result"]["isError"] is True
                        and r4.get("ok") is False
                        and "does not take" in r4.get("error", ""))
        check("O4 wire refuses metrics+task_id", refused_wire,
              json.dumps(r4)[:300])

        # ---- O5 negative CLI: stray operand ---------------------------------
        env = base_env(tmp / "o5")
        p = subprocess.run([str(BIN), "task", "metrics", "5"],
                           capture_output=True, text=True, env=env, timeout=30)
        stream = p.stdout if p.stdout.strip() else p.stderr
        rc5 = json.loads(stream)
        check("O5 cli refuses stray operand (loud, not silent-ok)",
              rc5.get("ok") is False and "5" in rc5.get("error", ""),
              stream[:300])

        # ---- O6 negative python (reference) ---------------------------------
        env = base_env(tmp / "o6")
        os.environ.update({k: env[k] for k in
                           ("AIOSH_HOME", "AIOSH_TASKS_DIR", "AIOSH_CONSTITUTION")})
        import importlib, aiosh_mcp.server as srv
        importlib.reload(srv)
        r6 = srv.aios_task(action="metrics", task_id=7)
        check("O6 python refuses metrics+task_id pre-gate (reference)",
              r6.get("ok") is False and "does not take 'task_id'" in r6.get("error", "")
              and "audit_id" not in r6,
              json.dumps(r6, default=str)[:300])

        # ---- O7 boundaries ---------------------------------------------------
        env = base_env(tmp / "o7")
        out = rust_wire(env, [init_req(),
                              {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                               "params": {"name": "aios.task",
                                          "arguments": {"action": "metrics"}}}])
        r7 = wire_result(out[2])
        check("O7a pristine: rows==0 verify_ok next_task==1",
              r7["data"]["audit"]["rows"] == 0
              and r7["data"]["audit"]["verify_ok"] is True
              and r7["data"]["tasks"]["next_task"] == 1
              and r7["data"]["audit"]["head_hash_prefix"] == "",
              json.dumps(r7)[:300])
        env2 = dict(env); env2["AIOSH_LEDGER_MAX_TEXT"] = "64"
        p = subprocess.run([str(BIN), "task", "metrics"], capture_output=True,
                           text=True, env=env2, timeout=30)
        rc7 = json.loads(p.stdout)
        check("O7b env override visible (max_text=64)",
              rc7["ok"] is True and rc7["data"]["config"]["max_text"] == 64,
              p.stdout[:200])
        env3 = dict(env); env3["AIOSH_LEDGER_MAX_TEXT"] = "63"
        p = subprocess.run([str(BIN), "task", "metrics"], capture_output=True,
                           text=True, env=env3, timeout=30)
        rc7c = json.loads(p.stderr if p.stderr.strip() else p.stdout)
        check("O7c env below floor -> loud named refusal",
              rc7c.get("ok") is False
              and "AIOSH_LEDGER_MAX_TEXT='63'" in rc7c.get("error", "")
              and "must be >= 64" in rc7c.get("error", ""),
              json.dumps(rc7c)[:300])

        # ---- O8 failure mode: corrupt state ----------------------------------
        env = base_env(tmp / "o8")
        (tmp / "o8" / "tasks" / "TASK_STATE.json").write_text("{broken",
                                                              encoding="utf-8")
        out = rust_wire(env, [init_req(),
                              {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                               "params": {"name": "aios.task",
                                          "arguments": {"action": "metrics"}}}])
        r8 = wire_result(out[2])
        check("O8a wire corrupt state -> loud ok:false",
              out[2]["result"]["isError"] is True and r8.get("ok") is False,
              json.dumps(r8)[:250])
        p = subprocess.run([str(BIN), "task", "metrics"], capture_output=True,
                           text=True, env=env, timeout=30)
        stream = p.stdout if p.stdout.strip() else p.stderr
        rc8 = json.loads(stream)
        tail_rows = subprocess.run(
            [str(BIN), "audit", "tail", "3"], capture_output=True,
            text=True, env=env, timeout=30)
        rows = json.loads(tail_rows.stdout)["data"]["rows"]
        honest_row = any(rr["tool"] in ("task.metrics", "task.ledger")
                         and rr["outcome"] in ("refused", "error") for rr in rows)
        check("O8b cli corrupt state -> ok:false AND honest audit row",
              rc8.get("ok") is False and honest_row,
              stream[:200] + " | tail:" + json.dumps(
                  [(rr["tool"], rr["outcome"]) for rr in rows]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    passed = sum(1 for _, ok in RESULTS if ok)
    print(f"\n{passed}/{len(RESULTS)} checks pass")
    return 0 if passed == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
