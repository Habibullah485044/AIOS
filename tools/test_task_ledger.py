"""Task Ledger Control — data model unit tests (T-00015).

Standalone test for `tools/task_ledger.py`, following the repo smoke-test
style (PASS/FAIL markers, non-zero exit on failure). Runs entirely in a
temp directory via the AIOSH_TASKS_DIR override — it never mutates the
real docs/tasks state.

Coverage:
  U1  v1 -> v2 state migration
  U2  in-order completion advances pointer + appends event + evidence stub
  U3  out-of-order completion refused (NO-SKIP) and state unchanged
  U4  unknown task id refused
  U5  block / unblock cycle (pointer held, then restored)
  U6  skip with mandatory reason advances pointer and records skip
  U7  boundary: completing the last task sets next_task to None
  U8  rebuild_state reconstructs pointer from the event log
  U9  corrupt event log line raises ValueError
  U10 ledger invariant validation catches id gaps / bad next_task
  U11 atomic save leaves no .tmp files behind
  U12 CLI subprocess: legacy positional mode, check, status, NO-SKIP exit code
  U13 broken-feature simulation: guard must reject wrong next_task
  U14 rebuild replays skip/unblock pointers (spec T-00022 §6)
  U15 rebuild clamps pointer at end of ledger
"""

from __future__ import annotations

try:
    import fcntl
except ImportError:  # T-02902: Windows has no fcntl — the holder below
    fcntl = None    # uses msvcrt (the same primitive the ledger uses)
import importlib.util
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
import time
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "task_ledger.py"

PASS = "[✓]"
FAIL = "[✗]"


def load_module(env_home: str):
    """Import task_ledger with AIOSH_TASKS_DIR pointed at the sandbox."""
    spec = importlib.util.spec_from_file_location("task_ledger_under_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    old = os.environ.get("AIOSH_TASKS_DIR")
    os.environ["AIOSH_TASKS_DIR"] = env_home
    try:
        spec.loader.exec_module(module)
    finally:
        if old is None:
            os.environ.pop("AIOSH_TASKS_DIR", None)
        else:
            os.environ["AIOSH_TASKS_DIR"] = old
    # Re-point module-level paths (constants were bound at import time).
    module.DOCS_TASKS = env_home
    module.LEDGER_PATH = os.path.join(env_home, "MASTER_TASK_LEDGER.jsonl")
    module.STATE_PATH = os.path.join(env_home, "TASK_STATE.json")
    module.EVENTS_PATH = os.path.join(env_home, "COMPLETIONS.jsonl")
    module.LOCK_PATH = os.path.join(env_home, ".TASK_STATE.lock")
    module.EVIDENCE_DIR = os.path.join(env_home, "evidence")
    return module


def make_ledger(path: Path, n: int = 3) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for i in range(1, n + 1):
            rec = {
                "id": i,
                "title": f"task {i}",
                "phase": "Phase 0 — Test",
                "status": "pending",
                "goal": f"goal {i}",
                "instructions": [f"step {i}"],
                "acceptance": [f"accept {i}"],
                "artifacts": [f"evidence/T-{i:05d}.md"],
                "depends_on": [] if i == 1 else [i - 1],
                "next_task": i + 1 if i < n else None,
            }
            f.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")


def make_v1_state(path: Path, total: int, next_task: int) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "ledger": "MASTER_TASK_LEDGER.jsonl",
            "total_tasks": total,
            "next_task": next_task,
            "completed": list(range(1, next_task)),
            "rule": "legacy",
        }, f)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="task-ledger-unit-"))
    tl = load_module(str(tmp))
    make_ledger(tmp / "MASTER_TASK_LEDGER.jsonl", n=3)
    make_v1_state(tmp / "TASK_STATE.json", total=3, next_task=1)

    # U1 — v1 -> v2 migration
    s = tl.load_state()
    ok = (s.get("schema_version") == 2 and s.get("blocked") == []
          and s.get("skipped") == [] and s.get("last_event_seq") == 0)
    print(f"{PASS if ok else FAIL} U1 v1->v2 migration")
    if not ok:
        return 1

    # U2 — in-order completion
    r = tl.complete_task(1, note="unit test")
    ev = tl.read_events()
    ok = (r["ok"] and r["next_task"] == 2 and len(ev) == 1
          and ev[0]["seq"] == 1 and ev[0]["event"] == "completed"
          and (tmp / "evidence" / "T-00001-completion.md").exists())
    print(f"{PASS if ok else FAIL} U2 in-order completion (event seq, pointer, evidence stub)")
    if not ok:
        return 1

    # U3 — NO-SKIP refusal, state unchanged
    before = tl.load_state()
    try:
        tl.complete_task(3)
        print(f"{FAIL} U3 out-of-order completion was allowed")
        return 1
    except PermissionError as e:
        ok = "NO-SKIP" in str(e) and tl.load_state() == before \
            and len(tl.read_events()) == 1
        print(f"{PASS if ok else FAIL} U3 no-skip refusal keeps state unchanged")
        if not ok:
            return 1

    # U4 — unknown task id
    try:
        tl.complete_task(999)
        print(f"{FAIL} U4 unknown task id accepted")
        return 1
    except PermissionError:
        # refused by no-skip before ledger lookup — still a refusal
        print(f"{PASS} U4 unknown/incorrect task id refused")
    except ValueError:
        print(f"{PASS} U4 unknown task id refused")

    # U5 — block / unblock
    rb = tl.block_task(2, "blocked for test")
    ok = rb["ok"] and rb["next_task"] == 2 and 2 in tl.load_state()["blocked"]
    if ok:
        ru = tl.unblock_task(2, "unblocked for test")
        ok = ru["ok"] and ru["next_task"] == 2 and 2 not in tl.load_state()["blocked"]
    print(f"{PASS if ok else FAIL} U5 block/unblock cycle")
    if not ok:
        return 1

    # U6 — skip with reason
    rs = tl.skip_task(2, "human override in unit test")
    s = tl.load_state()
    ok = rs["ok"] and rs["next_task"] == 3 and 2 in s["skipped"] \
        and tl.read_events()[-1]["event"] == "pointer_reset"
    print(f"{PASS if ok else FAIL} U6 skip records pointer_reset and advances")
    if not ok:
        return 1

    # U7 — boundary: last task -> next_task None
    r = tl.complete_task(3, note="last task")
    ok = r["ok"] and r["next_task"] is None
    print(f"{PASS if ok else FAIL} U7 last task sets next_task=None")
    if not ok:
        return 1

    # U8 — rebuild from event log
    # (D4 replay: pointer reproduces LIVE transitions — completing the
    # last task leaves next_task None, exactly as U7 observed live.)
    rebuilt = tl.rebuild_state()
    ok = (rebuilt["completed"] == [1, 3] and rebuilt["skipped"] == [2]
          and rebuilt["next_task"] is None and rebuilt["last_event_seq"] == 5)
    print(f"{PASS if ok else FAIL} U8 rebuild_state from event log")
    if not ok:
        print("   rebuilt:", rebuilt)
        return 1

    # U9 — corrupt event log detected
    with open(tl.EVENTS_PATH, "a", encoding="utf-8") as f:
        f.write("{corrupt line\n")
    try:
        tl.read_events()
        print(f"{FAIL} U9 corrupt event log not detected")
        return 1
    except ValueError:
        print(f"{PASS} U9 corrupt event log raises ValueError")
    # restore log by truncating the corrupt last line
    lines = Path(tl.EVENTS_PATH).read_text(encoding="utf-8").splitlines()
    Path(tl.EVENTS_PATH).write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    # U10 — ledger invariant validation
    ok_good = tl.assert_ledger_invariants()["ok"]
    bad_ledger = tmp / "BAD.jsonl"
    bad_ledger.write_text(
        json.dumps({"id": 1, "depends_on": [], "next_task": 3}) + "\n",
        encoding="utf-8")
    bad = tl.assert_ledger_invariants(str(bad_ledger))
    ok = ok_good and not bad["ok"] and "next_task" in bad["error"]
    print(f"{PASS if ok else FAIL} U10 ledger invariants (good passes, tampered fails)")
    if not ok:
        return 1

    # U11 — atomic save leaves no temp files
    leftovers = [p for p in tmp.iterdir() if ".tmp." in p.name]
    ok = not leftovers
    print(f"{PASS if ok else FAIL} U11 no leftover tmp files after atomic saves")
    if not ok:
        return 1

    # U12 — CLI subprocess (legacy positional + subcommands), sandboxed env
    env = {**os.environ, "AIOSH_TASKS_DIR": str(tmp)}
    # state now: next_task=4 after rebuild; create a 4-task ledger context
    make_ledger(tmp / "MASTER_TASK_LEDGER.jsonl", n=4)
    st = json.loads(Path(tl.STATE_PATH).read_text(encoding="utf-8"))
    st["total_tasks"] = 4
    st["next_task"] = 4
    tl.save_state_atomic(st)

    p1 = subprocess.run(
        [sys.executable, str(MODULE_PATH), "4", "--note", "cli legacy"],
        env=env, capture_output=True, text=True)
    p2 = subprocess.run(
        [sys.executable, str(MODULE_PATH), "6"],
        env=env, capture_output=True, text=True)
    p3 = subprocess.run(
        [sys.executable, str(MODULE_PATH), "check"],
        env=env, capture_output=True, text=True)
    p4 = subprocess.run(
        [sys.executable, str(MODULE_PATH), "status"],
        env=env, capture_output=True, text=True)
    j1, j2, j3, j4 = (json.loads(p.stdout) for p in (p1, p2, p3, p4))
    ok = (p1.returncode == 0 and j1["ok"] and j1["next_task"] is None
          and p2.returncode == 1 and j2["ok"] is False and "NO-SKIP" in j2["error"]
          and p3.returncode == 0 and j3["ok"] is True
          and p4.returncode == 0 and j4["completed"] == [1, 3, 4])
    print(f"{PASS if ok else FAIL} U12 CLI legacy mode, NO-SKIP exit code, check, status")
    if not ok:
        print("   ", p1.stdout, p2.stdout, p3.stdout, p4.stdout)
        return 1

    # U13 — broken-feature simulation: point the state at a valid task id,
    # then patch find_task_in_ledger to report it missing. complete_task must
    # pass the NO-SKIP guard (id == next_task) and then refuse with
    # ValueError — proving the ledger lookup is a real second gate.
    st = tl.load_state()
    st["next_task"] = 2
    tl.save_state_atomic(st)
    orig_find = tl.find_task_in_ledger
    tl.find_task_in_ledger = lambda task_id, ledger_path=None: None
    try:
        tl.complete_task(2)
        print(f"{FAIL} U13 broken feature not detected")
        return 1
    except ValueError:
        print(f"{PASS} U13 missing-task lookup refused after no-skip guard")
    finally:
        tl.find_task_in_ledger = orig_find

    # U14 — rebuild replays skip/unblock pointers (spec T-00022 §6,
    # mirrors ledger.rs::rebuild_replays_skip_and_unblock_pointers)
    tmp2 = Path(tempfile.mkdtemp(prefix="task-ledger-unit2-"))
    tl2 = load_module(str(tmp2))
    make_ledger(tmp2 / "MASTER_TASK_LEDGER.jsonl", n=5)
    make_v1_state(tmp2 / "TASK_STATE.json", total=5, next_task=1)
    tl2.complete_task(1, note="a")            # next=2
    tl2.block_task(2, "wait")                 # pointer held
    tl2.unblock_task(2, "retry")              # next=2
    tl2.skip_task(2, "scope")                 # next=3
    tl2.complete_task(3, note="c")            # next=4
    (tmp2 / "TASK_STATE.json").write_text("{}", encoding="utf-8")
    st = tl2.rebuild_state()
    ok = (st["next_task"] == 4 and st["completed"] == [1, 3]
          and st["skipped"] == [2] and st["blocked"] == []
          and st["last_event_seq"] == 5)
    print(f"{PASS if ok else FAIL} U14 rebuild replays skip/unblock pointers")
    if not ok:
        print("   rebuilt:", st)
        return 1

    # U15 — end-of-ledger clamp on replay (pointer_reset at last task)
    tmp3 = Path(tempfile.mkdtemp(prefix="task-ledger-unit3-"))
    tl3 = load_module(str(tmp3))
    make_ledger(tmp3 / "MASTER_TASK_LEDGER.jsonl", n=3)
    make_v1_state(tmp3 / "TASK_STATE.json", total=3, next_task=1)
    tl3.complete_task(1, note="a")
    tl3.complete_task(2, note="b")
    tl3.skip_task(3, "last")
    (tmp3 / "TASK_STATE.json").write_text("{}", encoding="utf-8")
    st = tl3.rebuild_state()
    ok = st["next_task"] is None and st["skipped"] == [3] \
        and st["completed"] == [1, 2]
    print(f"{PASS if ok else FAIL} U15 rebuild clamps pointer at end of ledger")
    if not ok:
        print("   rebuilt:", st)
        return 1

    # U16 — bounded lock wait (T-00028): a stuck holder must produce an
    # explicit PermissionError after the deadline, never hang.
    tmp4 = Path(tempfile.mkdtemp(prefix="task-ledger-unit4-"))
    tl4 = load_module(str(tmp4))
    make_ledger(tmp4 / "MASTER_TASK_LEDGER.jsonl", n=3)
    make_v1_state(tmp4 / "TASK_STATE.json", total=3, next_task=1)
    tl4.LOCK_TIMEOUT_SECS = 0.2
    if os.name == "nt":
        import msvcrt
        holder_fd = os.open(tl4.LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o644)
        msvcrt.locking(holder_fd, msvcrt.LK_LOCK, 1)
    else:
        holder_fd = os.open(tl4.LOCK_PATH, os.O_WRONLY | os.O_CREAT, 0o644)
        fcntl.flock(holder_fd, fcntl.LOCK_EX)
    try:
        started = time.monotonic()
        try:
            tl4.complete_task(1)
            print(f"{FAIL} U16 lock contention did not refuse")
            return 1
        except PermissionError as e:
            waited = time.monotonic() - started
            ok = "lock busy" in str(e) and waited >= 0.15
            print(f"{PASS if ok else FAIL} U16 stuck holder -> explicit lock-busy error ({waited:.2f}s)")
            if not ok:
                print("   ", e)
                return 1
    finally:
        if os.name == "nt":
            msvcrt.locking(holder_fd, msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(holder_fd, fcntl.LOCK_UN)
        os.close(holder_fd)
    # Lock free again -> mutation proceeds normally.
    r = tl4.complete_task(1, note="after release")
    ok = r["ok"] is True
    print(f"{PASS if ok else FAIL} U16b mutation succeeds once lock released")
    if not ok:
        return 1

    print()
    print("PASS: task ledger unit tests (U1..U16)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
