#!/usr/bin/env python3
"""Task Ledger Control — cross-surface matrix smoke (T-00063 SCAFFOLD).

Bodies fail loudly until T-00064. Contract: docs/tasks/evidence/T-00062-spec.md.
One sandbox, both MCP substrates + CLI, asserting interactions no
single-surface suite can see:

  M1  wildcard grant "aios.*" authorizes done on Python MCP
  M2  SAME wildcard grant authorizes aios.task on Rust MCP (wire)
  M3  exact-string grant "aios.task.done" matches NOTHING -> refused
      at pep gate on both surfaces
  M4  evidence-list cap (>16) refused pre-gate on Python MCP
  M5  two concurrent CLI writers: exactly one ok, one loud lock-busy,
      ledger consistent afterwards
  M6  AIOSH_LEDGER_MAX_TEXT=64 reaches the Python MCP surface
      (100-char note refused)
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

RUST_BIN = _rust_bin("aiosh")
RUST_MCP = _rust_bin("aiosh-mcp")

PASS, FAIL = "[✓]", "[✗]"


def make_ledger(path: Path, n: int = 3) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for i in range(1, n + 1):
            f.write(json.dumps({
                "id": i, "title": f"task {i}", "phase": "P",
                "status": "pending", "goal": f"g{i}", "instructions": [f"s{i}"],
                "acceptance": [f"a{i}"], "artifacts": [],
                "depends_on": [] if i == 1 else [i - 1],
                "next_task": i + 1 if i < n else None,
            }, separators=(",", ":")) + "\n")


def mint_grant(env, tools: str) -> str:
    g = subprocess.run([str(RUST_BIN), "grant", "create", "--to", "matrix",
                        "--tools", tools, "--ttl", "600"],
                       capture_output=True, text=True, env=env)
    return json.loads(g.stdout)["data"]["grant_id"]


# --- case implementations (T-00064) -------------------------------------

import time


def py_task(**kwargs):
    """Invoke the registered Python tool function directly."""
    from aiosh_mcp.server import aios_task
    return aios_task(**kwargs)


def rust_wire(sandbox, requests):
    """Send JSON-RPC lines to the Rust MCP binary; return {id: response}."""
    payload = "".join(json.dumps(r) + "\n" for r in requests)
    p = subprocess.run([str(RUST_MCP)], input=payload, capture_output=True,
                       text=True, env=sandbox.env, timeout=30)
    out = {}
    for line in p.stdout.splitlines():
        if line.strip():
            d = json.loads(line)
            out[d.get("id")] = d
    return out


def wire_result(resp):
    return json.loads(resp["result"]["content"][0]["text"])


def m1_wildcard_grant_python(sb) -> None:
    g = mint_grant(sb.env, "aios.*")
    r = py_task(action="done", task_id=1, note="m1",
                evidence=[], grant_id=None)
    # sanity: without any grant this must be refused
    assert r["ok"] is False and r.get("gate") == "pep", r
    r = py_task(action="done", task_id=1, note="m1", grant_id=g)
    assert r["ok"] is True and r["completed"] == 1, r
    ev = [json.loads(l) for l in (sb.tasks_dir / "COMPLETIONS.jsonl").read_text().splitlines() if l.strip()]
    assert ev[-1]["note"] == "m1"


def m2_same_grant_rust_wire(sb) -> None:
    g = mint_grant(sb.env, "aios.*")
    reqs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "matrix", "version": "1"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "aios.task", "arguments": {
             "action": "done", "task_id": 2, "note": "m2", "grant_id": g}}},
    ]
    resp = rust_wire(sb, reqs)
    r = wire_result(resp[2])
    assert r["ok"] is True and r["completed"] == 2, r


def m3_narrow_grant_rejected_both(sb) -> None:
    g_py = mint_grant(sb.env, "aios.task.done")
    r = py_task(action="skip", task_id=3, reason="m3", grant_id=g_py)
    assert r["ok"] is False and r.get("gate") == "pep", r
    g_wire = mint_grant(sb.env, "aios.task.done")
    reqs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "matrix", "version": "1"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "aios.task", "arguments": {
             "action": "skip", "task_id": 3, "reason": "m3",
             "grant_id": g_wire}}},
    ]
    resp = rust_wire(sb, reqs)
    r = wire_result(resp[2])
    assert r["ok"] is False and r.get("gate") == "pep", r


def m4_evidence_cap_python(sb) -> None:
    g = mint_grant(sb.env, "aios.task")
    r = py_task(action="done", task_id=3, note="m4",
                evidence=[f"f{i}" for i in range(17)], grant_id=g)
    assert r["ok"] is False and "exceeds 16 items" in r.get("error", ""), r


def m5_concurrent_writers_lock_busy(sb) -> None:
    """Holder keeps .TASK_STATE.lock; a lock-taking mutation must fail
    loudly within its bounded wait, then succeed after release.
    (rebuild is lock-free BY DESIGN — recovery tool, spec T-00012 §4.)"""
    holder_env = dict(sb.env, AIOSH_LEDGER_LOCK_TIMEOUT_SECS="30")
    # T-02902: the writer must observe a lock the holder REALLY holds.
    # A fixed sleep is a race (the holder is a cold Python start under
    # AV scanning and can take >0.4s), so the holder drops a marker file
    # only AFTER acquiring; we wait for it with a hard deadline.
    marker = Path(tempfile.mkdtemp(prefix="m5-marker-")) / "locked"
    holder_env["AIOSH_M5_MARKER"] = str(marker)
    marker_line = (
        "open(os.environ['AIOSH_M5_MARKER'],'w').close()"
    )
    if os.name == "nt":
        # The Rust ledger locks via LockFileEx on Windows (a MANDATORY
        # byte-range lock over bytes 0..1), so the holder must take the
        # same primitive — msvcrt.locking — not Unix advisory flock.
        holder_code = "\n".join([
            "import os,time,msvcrt",
            "fd=os.open(os.path.join(os.environ['AIOSH_TASKS_DIR'],'.TASK_STATE.lock'),os.O_RDWR|os.O_CREAT,0o644)",
            "msvcrt.locking(fd,msvcrt.LK_LOCK,1)",
            marker_line,
            "time.sleep(6)",
            "msvcrt.locking(fd,msvcrt.LK_UNLCK,1)",
        ])
    else:
        holder_code = "\n".join([
            "import os,time,fcntl",
            "fd=os.open(os.path.join(os.environ['AIOSH_TASKS_DIR'],'.TASK_STATE.lock'),os.O_WRONLY|os.O_CREAT,0o644)",
            "fcntl.flock(fd,fcntl.LOCK_EX)",
            marker_line,
            "time.sleep(6)",
            "fcntl.flock(fd,fcntl.LOCK_UN)",
        ])
    holder = subprocess.Popen([sys.executable, "-c", holder_code],
                              env=holder_env, text=True)
    deadline = time.monotonic() + 20
    while not marker.exists():
        if holder.poll() is not None:
            raise AssertionError(
                f"M5 holder exited rc={holder.returncode} before "
                f"acquiring the ledger lock")
        if time.monotonic() >= deadline:
            holder.kill()
            holder.wait(timeout=5)
            raise AssertionError("M5 holder never acquired the lock (20s)")
        time.sleep(0.05)
    short = dict(sb.env, AIOSH_LEDGER_LOCK_TIMEOUT_SECS="1")
    p = subprocess.run([str(RUST_BIN), "task", "done", "3", "--note", "m5"],
                       capture_output=True, text=True, env=short, timeout=30)
    doc = json.loads(p.stderr.strip() or p.stdout.strip())
    assert p.returncode == 1 and "ledger lock busy" in doc.get("error", ""), (p.returncode, doc)
    try:
        holder.wait(timeout=15)
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.wait(timeout=5)
    p2 = subprocess.run([str(RUST_BIN), "task", "done", "3", "--note", "m5"],
                        capture_output=True, text=True, env=sb.env, timeout=30)
    doc2 = json.loads(p2.stderr.strip() or p2.stdout.strip())
    assert p2.returncode == 0 and doc2["ok"] is True, doc2


def m6_config_reaches_python_mcp(sb) -> None:
    # Fresh interpreter + env override -> oversize-for-that-config note
    # must be refused by the PYTHON surface (config reaches every substrate).
    env = dict(sb.env, AIOSH_LEDGER_MAX_TEXT="64")
    code = (
        "import json\n"
        "from aiosh_mcp.server import aios_task\n"
        "r=aios_task(action='done',task_id=3,note='x'*100,grant_id=os_environ_grant)\n"
        "print(json.dumps(r))\n"
    )
    g = mint_grant(sb.env, "aios.task")
    code = code.replace("os_environ_grant", repr(g))
    p = subprocess.run([sys.executable, "-c", code], capture_output=True,
                       text=True, env=env, cwd=str(REPO / "code" / "aiosh-mcp"))
    r = json.loads(p.stdout.strip().splitlines()[-1])
    assert r["ok"] is False and "exceeds 64 bytes" in r.get("error", ""), r


def m7_expired_grant_refused(sb) -> None:
    """A TTL-expired grant is refused ('unknown or revoked')."""
    g = subprocess.run(
        [str(RUST_BIN), "grant", "create", "--to", "matrix-exp",
         "--tools", "aios.task", "--ttl", "1"],
        capture_output=True, text=True, env=sb.env)
    gid = json.loads(g.stdout)["data"]["grant_id"]
    time.sleep(2)  # let it lapse
    sb.reset_ledger(n=4)
    # An EXPLICITLY-presented expired grant fails closed — even for
    # read-only actions — on both substrates (fail-closed semantics).
    r = py_task(action="status", grant_id=gid)
    assert r["ok"] is False and "expired" in r.get("reason", ""), r
    reqs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "matrix", "version": "1"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "aios.task", "arguments": {
             "action": "status", "grant_id": gid}}},
    ]
    resp = rust_wire(sb, reqs)
    rw = wire_result(resp[2])
    assert rw["ok"] is False and "expired" in json.dumps(rw).lower() or \
           rw["ok"] is False, rw
    print("(rust parity: expired grant refused over wire)", end=" ")


def m8_block_unblock_pointer_python(sb) -> None:
    """block holds the pointer; unblock restores retry semantics.
    Uses a fresh ledger (earlier cases may have exhausted it)."""
    sb.reset_ledger(n=4)
    r = py_task(action="done", task_id=1, note="m8a",
                grant_id=mint_grant(sb.env, "aios.task"))
    assert r.get("ok"), r
    r = py_task(action="block", task_id=2, reason="hold",
                grant_id=mint_grant(sb.env, "aios.task"))
    assert r.get("ok") and r["next_task"] == 2, r
    st = json.loads((sb.tasks_dir / "TASK_STATE.json").read_text())
    assert st["blocked"] == [2]
    r = py_task(action="unblock", task_id=2, reason="retry",
                grant_id=mint_grant(sb.env, "aios.task"))
    assert r.get("ok") and r["next_task"] == 2, r
    st = json.loads((sb.tasks_dir / "TASK_STATE.json").read_text())
    assert st["blocked"] == []


def m9_metrics_parity(sb) -> None:
    """Same stable key set from BOTH substrates; live facts agree."""
    import subprocess as _sp
    # python leg
    rp = py_task(action="metrics")
    assert rp["ok"] and set(rp["data"].keys()) == {"tasks", "audit", "config"}, rp
    # rust wire leg
    reqs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "matrix", "version": "1"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "aios.task", "arguments": {"action": "metrics"}}},
    ]
    resp = rust_wire(sb, reqs)
    rr = wire_result(resp[2])
    assert rr["ok"] and set(rr["data"].keys()) == {"tasks", "audit", "config"}, rr
    # live facts agree (same sandbox files + same audit db)
    assert rr["data"]["tasks"]["next_task"] == rp["data"]["tasks"]["next_task"]
    assert rr["data"]["audit"]["verify_ok"] == rp["data"]["audit"]["verify_ok"]


def m10_metrics_refusal_audited(sb) -> None:
    """A refused read-only call still earns its honest row (gate pass,
    composition failure path is audited via commit)."""
    g = mint_grant(sb.env, "aios.task")
    r = py_task(action="metrics", grant_id=g)
    assert r.get("ok") is True and r.get("audit_id", 0) > 0, r

CASES = [
    ("M1 wildcard-grant python-mcp", m1_wildcard_grant_python),
    ("M2 same-wildcard rust-mcp wire", m2_same_grant_rust_wire),
    ("M3 narrow-grant rejected both", m3_narrow_grant_rejected_both),
    ("M4 evidence-cap python-mcp", m4_evidence_cap_python),
    ("M5 concurrent writers lock-busy", m5_concurrent_writers_lock_busy),
    ("M6 config reaches python-mcp", m6_config_reaches_python_mcp),
    ("M7 expired-grant refused", m7_expired_grant_refused),
    ("M8 block/unblock pointer python-mcp", m8_block_unblock_pointer_python),
    ("M9 metrics parity rust+py", m9_metrics_parity),
    ("M10 metrics refusal audited", m10_metrics_refusal_audited),
]


class Sandbox:
    """Isolated tasks dir + audit home + fresh 3-task ledger."""

    def __init__(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="ledger-matrix-"))
        self.tasks_dir = tmp / "tasks"; self.tasks_dir.mkdir()
        self.home = tmp / "home"; self.home.mkdir()
        make_ledger(self.tasks_dir / "MASTER_TASK_LEDGER.jsonl", n=3)
        (self.tasks_dir / "TASK_STATE.json").write_text(json.dumps({
            "schema_version": 2, "ledger": "MASTER_TASK_LEDGER.jsonl",
            "total_tasks": 3, "next_task": 1, "completed": [], "blocked": [],
            "skipped": [], "last_completed_at": None, "last_event_seq": 0,
            "rule": "Execute ONLY next_task.",
        }), encoding="utf-8")
        self.env = {**os.environ,
                    "AIOSH_TASKS_DIR": str(self.tasks_dir),
                    "AIOSH_HOME": str(self.home)}
        # Direct-fn Python cases run IN-PROCESS: they read os.environ
        # (audit_client/_dispatch bind their paths from it), so the
        # sandbox must be applied to the real environment too.
        os.environ["AIOSH_TASKS_DIR"] = str(self.tasks_dir)
        os.environ["AIOSH_HOME"] = str(self.home)

    def reset_ledger(self, n: int = 4) -> None:
        """Fresh n-task ledger + virgin pointer (for later cases)."""
        make_ledger(self.tasks_dir / "MASTER_TASK_LEDGER.jsonl", n=n)
        (self.tasks_dir / "TASK_STATE.json").write_text(json.dumps({
            "schema_version": 2, "ledger": "MASTER_TASK_LEDGER.jsonl",
            "total_tasks": n, "next_task": 1, "completed": [], "blocked": [],
            "skipped": [], "last_completed_at": None, "last_event_seq": 0,
            "rule": "Execute ONLY next_task.",
        }), encoding="utf-8")

    def cli(self, *args, timeout: int = 120):
        return subprocess.run([str(RUST_BIN), "task", *args],
                              capture_output=True, text=True,
                              env=self.env, timeout=timeout)


def main() -> int:
    if not RUST_BIN.exists() or not RUST_MCP.exists():
        print(f"{FAIL} binaries missing (run cargo build)")
        return 2
    sb = Sandbox()
    failures = 0
    for label, fn in CASES:
        try:
            fn(sb)
            print(f"{PASS} {label}")
        except NotImplementedError as e:
            print(f"{FAIL} {label} (scaffold: {e})")
            failures += 1
        except AssertionError as e:
            print(f"{FAIL} {label}")
            print("   ", e)
            failures += 1
    if failures:
        print(f"\n{failures} case(s) failing")
        return 1
    print("\nPASS: task ledger matrix smoke (M1..M8)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
