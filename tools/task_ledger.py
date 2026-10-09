#!/usr/bin/env python3
"""Task Ledger Control — data model implementation (T-00014).

Implements docs/tasks/evidence/T-00012-data-model-specification.md:
  - Atomic state pointer updates (tmp + os.replace)
  - Append-only completion event log (COMPLETIONS.jsonl)
  - Strict no-skip enforcement with mechanical refusal
  - Block / unblock / skip with explicit audit events
  - State rebuild from event log (Fowler complete-rebuild)
  - Ledger invariant validation

Single-writer assumption (D3): advisory flock guards against accidental
concurrent runs on the same host.
"""

from __future__ import annotations

import errno
try:
    import fcntl
except ImportError:
    fcntl = None
import glob
import json
import os
import re
import sys
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

DOCS_TASKS = os.environ.get("AIOSH_TASKS_DIR") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "docs", "tasks")
LEDGER_PATH = os.path.join(DOCS_TASKS, "MASTER_TASK_LEDGER.jsonl")
STATE_PATH = os.path.join(DOCS_TASKS, "TASK_STATE.json")
EVENTS_PATH = os.path.join(DOCS_TASKS, "COMPLETIONS.jsonl")
LOCK_PATH = os.path.join(DOCS_TASKS, ".TASK_STATE.lock")
EVIDENCE_DIR = os.path.join(DOCS_TASKS, "evidence")

SCHEMA_VERSION = 2
VALID_EVENTS = ("completed", "blocked", "unblocked", "pointer_reset")

_RULE = ("Execute ONLY next_task. Advance by exactly 1 via "
         "tools/complete_task.py. Never skip.")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ----------------------------------------------------------------------
# State pointer
# ----------------------------------------------------------------------

def load_state(path: str = STATE_PATH) -> dict[str, Any]:
    """Load TASK_STATE.json, migrating v1 → v2 on read (spec §2.3)."""
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    if raw.get("schema_version", 1) >= SCHEMA_VERSION:
        return raw
    # v1 → v2 migration: add missing fields
    events = read_events(os.path.join(os.path.dirname(path), "COMPLETIONS.jsonl"))
    raw["schema_version"] = SCHEMA_VERSION
    raw.setdefault("blocked", [])
    raw.setdefault("skipped", [])
    raw["last_event_seq"] = events[-1]["seq"] if events else 0
    raw["rule"] = _RULE
    return raw


def save_state_atomic(state: dict[str, Any], path: str = STATE_PATH) -> None:
    """Write state to <path>.tmp.<pid> then os.replace() (spec §3)."""
    tmp = f"{path}.tmp.{os.getpid()}"
    data = json.dumps(state, indent=2, ensure_ascii=False) + "\n"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        os.write(fd, data.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


# ----------------------------------------------------------------------
# Event log
# ----------------------------------------------------------------------

def append_event(events_path: str, event: dict[str, Any],
                 expected_task_id: int | None = None) -> dict[str, Any]:
    """Append one JSONL event line (flush + fsync). Assigns seq."""
    kind = event.get("event")
    if kind not in VALID_EVENTS:
        raise ValueError(f"invalid event type: {kind!r}")
    if expected_task_id is not None and event.get("task_id") != expected_task_id:
        raise ValueError(
            f"event task_id {event.get('task_id')} != expected {expected_task_id}")
    existing = read_events(events_path)
    seq = (existing[-1]["seq"] + 1) if existing else 1
    record = {"seq": seq, "ts": _utcnow_iso(), **event}
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    fd = os.open(events_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return record


def read_events(events_path: str = EVENTS_PATH) -> list[dict[str, Any]]:
    """Read all events in order. Missing file => empty list."""
    if not os.path.exists(events_path):
        return []
    events = []
    with open(events_path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"corrupt event log line {i}: {e}") from e
    return events


def _replay_events(events: list[dict[str, Any]]) -> tuple[
        list[int], list[int], list[int], int, str | None]:
    """Core deterministic replay shared by rebuild_state and validate_state.

    Pointer semantics (spec T-00022 §6): completed t => next=t+1;
    unblocked t => next=t; pointer_reset t => next=t+1; blocked never
    moves the pointer. Returns (completed, blocked, skipped, next_pointer,
    last_ts).
    """
    completed: list[int] = []
    blocked: list[int] = []
    skipped: list[int] = []
    last_ts = None
    next_pointer = 1
    for ev in events:
        tid = ev.get("task_id")
        kind = ev.get("event")
        if kind == "completed" and tid is not None:
            completed.append(tid)
            last_ts = ev.get("ts", last_ts)
            next_pointer = tid + 1
        elif kind == "blocked" and tid is not None:
            if tid not in blocked:
                blocked.append(tid)
        elif kind == "unblocked" and tid is not None:
            blocked = [b for b in blocked if b != tid]
            next_pointer = tid
        elif kind == "pointer_reset" and tid is not None:
            skipped.append(tid)
            next_pointer = tid + 1
    return completed, blocked, skipped, next_pointer, last_ts


def rebuild_state(events_path: str = EVENTS_PATH,
                  ledger_path: str = LEDGER_PATH,
                  state_path: str = STATE_PATH,
                  total_tasks: int | None = None) -> dict[str, Any]:
    """Recompute TASK_STATE.json from the append-only event log.

    Pointer replay (spec T-00022 §6, fixes SPEC-TASK-LEDGER L3):
    deterministic event-order replay reproducing live transitions —
    completed t => next=t+1; unblocked t => next=t; pointer_reset t =>
    next=t+1; blocked never moves the pointer. A pointer past
    total_tasks collapses to None (end of ledger). Mirrors
    aiosh-core/src/ledger.rs::rebuild_state.
    """
    events = read_events(events_path)
    completed, blocked, skipped, next_pointer, last_ts = _replay_events(events)
    if total_tasks is None:
        total_tasks = _count_ledger_lines(ledger_path)
    if os.path.exists(ledger_path):
        sync_ledger_statuses(completed, blocked, skipped, ledger_path=ledger_path)
    next_task = None if next_pointer > total_tasks else next_pointer
    state = {
        "schema_version": SCHEMA_VERSION,
        "ledger": os.path.relpath(ledger_path, os.path.dirname(state_path)),
        "total_tasks": total_tasks,
        "next_task": next_task,
        "completed": completed,
        "blocked": blocked,
        "skipped": skipped,
        "last_completed_at": last_ts,
        "last_event_seq": events[-1]["seq"] if events else 0,
        "rule": _RULE,
    }
    save_state_atomic(state, state_path)
    return state


def _count_ledger_lines(ledger_path: str) -> int:
    count = 0
    with open(ledger_path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                count += 1
    return count


# ----------------------------------------------------------------------
# Validation (recovery & validation component, T-00103 scaffold)
# ----------------------------------------------------------------------

def validate_state(state_path: str = STATE_PATH,
                   events_path: str = EVENTS_PATH,
                   ledger_path: str = LEDGER_PATH) -> dict[str, Any]:
    """Read-only integrity report: live state vs event-log replay.

    Contract: docs/tasks/evidence/T-00102-spec.md §4. Report-only by
    design; `rebuild_state` remains the only repair path. Never mutates
    state, events, or evidence. Findings key set is the cross-substrate
    parity contract (Python == Rust == MCP == CLI).
    """
    live = load_state(state_path)
    events = read_events(events_path)
    total = _count_ledger_lines(ledger_path)
    completed_r, blocked_r, skipped_r, next_pointer, _ts = _replay_events(events)
    replay_next = None if next_pointer > total else next_pointer

    # G1 — drift between live state and replay.
    drift_fields: list[str] = []
    details: list[str] = []
    for field, rv in (("next_task", replay_next),
                      ("completed", completed_r),
                      ("blocked", blocked_r),
                      ("skipped", skipped_r)):
        lv = live.get(field)
        if lv != rv:
            drift_fields.append(field)
            # Compact-JSON rendering matches the Rust Value Display form
            # byte-for-byte (cross-substrate detail parity).
            details.append(
                f"{field} live={json.dumps(lv, separators=(',', ':'))} "
                f"replay={json.dumps(rv, separators=(',', ':'))}")
    drift_ok = not drift_fields
    checks_state = {
        "status": "ok" if drift_ok else "fatal",
        "detail": "; ".join(details) if details else None,
        "fields": drift_fields,
    }

    # G2 — event log seq integrity (contiguous 1..N) + last_event_seq.
    seqs = [ev.get("seq") for ev in events]
    seq_detail = None
    expected = list(range(1, len(seqs) + 1))
    if seqs != expected:
        bad_i = next(i for i, (a, b) in enumerate(zip(seqs, expected)) if a != b)
        seq_detail = (f"event {bad_i + 1}: seq={seqs[bad_i]!r} "
                      f"expected={expected[bad_i]!r}")
    live_seq = live.get("last_event_seq")
    if seq_detail is None and live_seq != len(seqs):
        seq_detail = f"last_event_seq live={live_seq!r} events={len(seqs)}"
    checks_seq = {"status": "ok" if seq_detail is None else "fatal",
                  "detail": seq_detail}

    # G5 — pointer range sanity on the REPLAYED pointer.
    ptr_detail = None
    if replay_next is not None:
        if replay_next in completed_r:
            ptr_detail = f"next_task {replay_next} is already completed"
        elif replay_next in blocked_r:
            ptr_detail = f"next_task {replay_next} is currently blocked"
        elif replay_next > total:
            ptr_detail = f"next_task {replay_next} beyond total_tasks {total}"
    checks_ptr = {"status": "ok" if ptr_detail is None else "fatal",
                  "detail": ptr_detail}

    # G3+G4 — evidence existence + orphans (warnings, never fatal).
    missing: list[str] = []
    for ev in events:
        if ev.get("event") != "completed":
            continue
        for rel in ev.get("evidence") or []:
            # T-00108 hardening (finding F-1): a path is satisfiable ONLY
            # if it is relative and never escapes the two intended bases
            # (tasks dir / repo root). Absolute or ".."-containing strings
            # are classified missing (suspicious), never satisfied — an
            # event-controlled string must not attest arbitrary disk
            # locations. Existence checks read nothing.
            suspicious = (not isinstance(rel, str)) or os.path.isabs(rel) \
                or ".." in rel.split("/")
            if not suspicious:
                cand_tasks = os.path.join(DOCS_TASKS, rel)
                cand_repo = os.path.join(os.path.dirname(DOCS_TASKS), rel)
                if os.path.exists(cand_tasks) or os.path.exists(cand_repo):
                    continue
            missing.append(
                f"T-{ev.get('task_id', 0):05d}:"
                f"{rel if isinstance(rel, str) else repr(rel)}")
    import glob as _glob
    orphans: list[str] = []
    completed_set = set(completed_r)
    stub_re = re.compile(r"^T-(\d{5})-completion\.md$")
    for p in sorted(glob.glob(os.path.join(EVIDENCE_DIR, "*-completion.md"))):
        m = stub_re.match(os.path.basename(p))
        if m and int(m.group(1)) not in completed_set:
            orphans.append(os.path.basename(p))
    checks_ev = {"status": "ok" if not (missing or orphans) else "warning",
                 "missing": missing, "orphans": orphans}

    fatal = any(c["status"] == "fatal" for c in
                (checks_state, checks_seq, checks_ptr))
    return {
        "ok": True,
        "action": "validate",
        "consistent": not fatal,
        "checks": {
            "state_vs_events": checks_state,
            "event_seq": checks_seq,
            "pointer_range": checks_ptr,
            "evidence": checks_ev,
        },
        "replay": {
            "next_task": replay_next,
            "completed": len(completed_r),
            "blocked": len(blocked_r),
            "skipped": len(skipped_r),
            "events": len(events),
            "total_tasks": total,
        },
        "live": {
            "next_task": live.get("next_task"),
            "completed": len(live.get("completed", [])),
            "blocked": len(live.get("blocked", [])),
            "skipped": len(live.get("skipped", [])),
            "last_event_seq": live_seq,
        },
    }


# ----------------------------------------------------------------------
# Ledger access
# ----------------------------------------------------------------------

def find_task_in_ledger(task_id: int,
                        ledger_path: str = LEDGER_PATH) -> dict[str, Any] | None:
    """Stream-scan the ledger for the task with the given id."""
    needle = f'"id": {task_id},'
    needle_compact = f'"id":{task_id},'
    with open(ledger_path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            if needle in line or needle_compact in line:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as e:
                    raise ValueError(
                        f"ledger line {i} unparseable: {e}") from e
                if rec.get("id") == task_id:
                    return rec
    return None


def assert_ledger_invariants(ledger_path: str = LEDGER_PATH) -> dict[str, Any]:
    """Validate spec §2.1 invariants."""
    prev_id = 0
    count = 0
    with open(ledger_path, encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as e:
                return {"ok": False, "line": i, "error": f"parse: {e}"}
            tid = rec.get("id")
            if tid != prev_id + 1:
                return {"ok": False, "line": i,
                        "error": f"id gap: expected {prev_id+1}, got {tid}"}
            deps = rec.get("depends_on", [])
            if tid > 1 and deps != [tid - 1]:
                return {"ok": False, "line": i,
                        "error": f"depends_on {deps} != [{tid-1}]"}
            nxt = rec.get("next_task")
            expected_next = tid + 1 if nxt is not None else None
            if nxt is not None and nxt != tid + 1:
                return {"ok": False, "line": i,
                        "error": f"next_task {nxt} != {tid+1}"}
            prev_id = tid
            count += 1
    # last task must have next_task null
    return {"ok": True, "total_tasks": count}


# ----------------------------------------------------------------------
# Locking
# ----------------------------------------------------------------------

def _env_float(name: str, default: float, lo: float) -> float:
    """T-00054: AIOSH_LEDGER_* env override with loud invalid errors
    (mirrors aiosh-core/src/ledger_config.rs)."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        v = float(raw)
    except ValueError:
        raise SystemExit(f"invalid {name}='{raw}': not a number")
    if v < lo:
        raise SystemExit(f"invalid {name}='{raw}': must be >= {lo}")
    if name == "AIOSH_LEDGER_LOCK_TIMEOUT_SECS" and v > 86400:
        raise SystemExit(f"invalid {name}='{raw}': must be <= 86400")
    return v


LOCK_TIMEOUT_SECS = _env_float("AIOSH_LEDGER_LOCK_TIMEOUT_SECS", 5.0, 1.0)
_LOCK_POLL_SECS = 0.05


@contextmanager
def acquire_lock(lock_path: str = LOCK_PATH):
    """Exclusive advisory lock (fcntl.flock), bounded wait (T-00028).

    Mirrors ledger.rs::acquire_lock_timeout: polls LOCK_NB until the
    deadline so a stuck holder yields an explicit PermissionError
    instead of hanging the process forever.
    """
    import time
    if fcntl is None:
        # T-02902: Windows now gets the same single-writer guard the Rust
        # ledger enforces there (ledger.rs win_lock: LockFileEx) — a
        # MANDATORY 1-byte range lock via msvcrt, polled until the same
        # bounded deadline with the same loud `ledger lock busy` error.
        # Previously this branch was a silent no-op, losing the
        # single-writer invariant on Windows entirely.
        import msvcrt
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o644)
        deadline = time.monotonic() + LOCK_TIMEOUT_SECS
        try:
            while True:
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise PermissionError(
                            f"ledger lock busy after "
                            f"{int(LOCK_TIMEOUT_SECS * 1000)}ms "
                            "(another writer holds .TASK_STATE.lock?)")
                    time.sleep(_LOCK_POLL_SECS)
            yield
        finally:
            try:
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
            os.close(fd)
        return
    fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o644)
    deadline = time.monotonic() + LOCK_TIMEOUT_SECS
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as e:
                if e.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                if time.monotonic() >= deadline:
                    raise PermissionError(
                        f"ledger lock busy after {int(LOCK_TIMEOUT_SECS * 1000)}ms "
                        "(another writer holds .TASK_STATE.lock?)") from e
                time.sleep(_LOCK_POLL_SECS)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# ----------------------------------------------------------------------
# Mutations
# ----------------------------------------------------------------------

def _fmt_task(tid: int | None) -> str:
    return "None" if tid is None else f"T-{tid:05d}"


def _ensure_evidence_stub(task_id: int, task: dict[str, Any]) -> str:
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    path = os.path.join(EVIDENCE_DIR, f"T-{task_id:05d}-completion.md")
    if not os.path.exists(path):
        lines = [f"# T-{task_id:05d} — {task.get('title', '')}\n\n",
                 f"Completed: {_utcnow_iso()}\n\n",
                 "Acceptance criteria:\n"]
        for a in task.get("acceptance", []):
            lines.append(f"- [x] {a}\n")
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)
    return path


def update_ledger_task_status(task_id: int, new_status: str,
                              ledger_path: str = LEDGER_PATH) -> bool:
    """Atomically rewrite task line in MASTER_TASK_LEDGER.jsonl with new status."""
    if not os.path.exists(ledger_path):
        return False
    tmp = f"{ledger_path}.tmp.{os.getpid()}"
    found = False
    needle = f'"id": {task_id},'
    needle_compact = f'"id":{task_id},'
    with open(ledger_path, "r", encoding="utf-8") as fin, \
         open(tmp, "w", encoding="utf-8") as fout:
        for line in fin:
            if not found and (needle in line or needle_compact in line):
                try:
                    rec = json.loads(line)
                    if rec.get("id") == task_id:
                        rec["status"] = new_status
                        line = json.dumps(rec, ensure_ascii=False) + "\n"
                        found = True
                except json.JSONDecodeError:
                    pass
            fout.write(line)
    if found:
        os.replace(tmp, ledger_path)
    else:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    return found


def sync_ledger_statuses(completed_ids: list[int] | set[int],
                         blocked_ids: list[int] | set[int] | None = None,
                         skipped_ids: list[int] | set[int] | None = None,
                         ledger_path: str = LEDGER_PATH) -> int:
    """Synchronize all statuses in MASTER_TASK_LEDGER.jsonl with event log replay."""
    if not os.path.exists(ledger_path):
        return 0
    completed_set = set(completed_ids)
    blocked_set = set(blocked_ids or [])
    skipped_set = set(skipped_ids or [])
    tmp = f"{ledger_path}.tmp.{os.getpid()}"
    updated = 0
    with open(ledger_path, "r", encoding="utf-8") as fin, \
         open(tmp, "w", encoding="utf-8") as fout:
        for line in fin:
            line_str = line.strip()
            if not line_str:
                fout.write(line)
                continue
            try:
                rec = json.loads(line_str)
                tid = rec.get("id")
                curr = rec.get("status")
                target = curr
                if tid in completed_set:
                    target = "done"
                elif tid in blocked_set:
                    target = "blocked"
                elif tid in skipped_set:
                    target = "skipped"
                else:
                    target = "pending"
                if curr != target:
                    rec["status"] = target
                    line = json.dumps(rec, ensure_ascii=False) + "\n"
                    updated += 1
            except json.JSONDecodeError:
                pass
            fout.write(line)
    os.replace(tmp, ledger_path)
    return updated


def complete_task(task_id: int, note: str = "",
                  evidence: list[str] | None = None) -> dict[str, Any]:
    """Spec §4: complete the current next_task and advance the pointer."""
    with acquire_lock(LOCK_PATH):
        state = load_state(STATE_PATH)
        if task_id != state["next_task"]:
            raise PermissionError(
                f"NO-SKIP violation: attempted to complete T-{task_id:05d} "
                f"but next_task is {_fmt_task(state['next_task'])}. "
                f"Complete {_fmt_task(state['next_task'])} first.")
        task = find_task_in_ledger(task_id, LEDGER_PATH)
        if task is None:
            raise ValueError(f"task {task_id} not found in ledger")
        append_event(EVENTS_PATH, {
            "event": "completed",
            "task_id": task_id,
            "note": note,
            "evidence": evidence or [],
        }, expected_task_id=task_id)
        state["completed"].append(task_id)
        state["next_task"] = task_id + 1 if task_id < state["total_tasks"] else None
        state["last_completed_at"] = _utcnow_iso()
        state["last_event_seq"] = state.get("last_event_seq", 0) + 1
        state["schema_version"] = SCHEMA_VERSION
        state.setdefault("blocked", [])
        state.setdefault("skipped", [])
        state["rule"] = _RULE
        save_state_atomic(state, STATE_PATH)
        update_ledger_task_status(task_id, "done", LEDGER_PATH)
        ev_file = _ensure_evidence_stub(task_id, task)
        return {"ok": True, "completed": task_id,
                "title": task.get("title"),
                "next_task": state["next_task"],
                "evidence": os.path.relpath(ev_file, DOCS_TASKS)}


def block_task(task_id: int, reason: str) -> dict[str, Any]:
    """Spec §5: mark the current task blocked; pointer does NOT advance."""
    if not reason:
        raise ValueError("block requires a non-empty reason")
    with acquire_lock(LOCK_PATH):
        state = load_state(STATE_PATH)
        if task_id != state["next_task"]:
            raise PermissionError(
                f"can only block next_task ({_fmt_task(state['next_task'])}), "
                f"got T-{task_id:05d}")
        append_event(EVENTS_PATH, {
            "event": "blocked", "task_id": task_id, "note": reason,
        }, expected_task_id=task_id)
        state.setdefault("blocked", [])
        if task_id not in state["blocked"]:
            state["blocked"].append(task_id)
        state["last_event_seq"] = state.get("last_event_seq", 0) + 1
        save_state_atomic(state, STATE_PATH)
        update_ledger_task_status(task_id, "blocked", LEDGER_PATH)
        return {"ok": True, "blocked": task_id, "next_task": state["next_task"]}


def unblock_task(task_id: int, reason: str) -> dict[str, Any]:
    """Spec §5: unblock a previously blocked task (retry)."""
    if not reason:
        raise ValueError("unblock requires a non-empty reason")
    with acquire_lock(LOCK_PATH):
        state = load_state(STATE_PATH)
        if task_id not in state.get("blocked", []):
            raise ValueError(f"task {task_id} is not in blocked list")
        append_event(EVENTS_PATH, {
            "event": "unblocked", "task_id": task_id, "note": reason,
        })
        state["blocked"] = [b for b in state["blocked"] if b != task_id]
        state["next_task"] = task_id
        state["last_event_seq"] = state.get("last_event_seq", 0) + 1
        save_state_atomic(state, STATE_PATH)
        update_ledger_task_status(task_id, "pending", LEDGER_PATH)
        return {"ok": True, "unblocked": task_id, "next_task": task_id}


def skip_task(task_id: int, reason: str) -> dict[str, Any]:
    """Spec §5: human override — skip with mandatory reason."""
    if not reason:
        raise ValueError("skip requires a non-empty reason")
    with acquire_lock(LOCK_PATH):
        state = load_state(STATE_PATH)
        if task_id != state["next_task"]:
            raise PermissionError(
                f"can only skip next_task ({_fmt_task(state['next_task'])}), "
                f"got T-{task_id:05d}")
        append_event(EVENTS_PATH, {
            "event": "pointer_reset", "task_id": task_id, "note": reason,
        }, expected_task_id=task_id)
        state.setdefault("skipped", [])
        state["skipped"].append(task_id)
        state["blocked"] = [b for b in state.get("blocked", []) if b != task_id]
        state["next_task"] = task_id + 1 if task_id < state["total_tasks"] else None
        state["last_event_seq"] = state.get("last_event_seq", 0) + 1
        save_state_atomic(state, STATE_PATH)
        update_ledger_task_status(task_id, "skipped", LEDGER_PATH)
        return {"ok": True, "skipped": task_id,
                "next_task": state["next_task"], "reason": reason}


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    import argparse
    if argv is None:
        argv = sys.argv[1:]
    # Legacy compat FIRST: bare `task_ledger.py <id> [--note S]` (argparse
    # subparsers would reject a bare numeric positional).
    if argv and argv[0].isdigit():
        tid = int(argv[0])
        note = ""
        if "--note" in argv:
            idx = argv.index("--note")
            if idx + 1 < len(argv):
                note = argv[idx + 1]
        try:
            result = complete_task(tid, note=note)
            print(json.dumps(result, indent=2))
            return 0
        except (PermissionError, ValueError) as e:
            print(json.dumps({"ok": False, "error": str(e)}, indent=2))
            return 1

    ap = argparse.ArgumentParser(description="Task ledger state machine")
    sub = ap.add_subparsers(dest="cmd")

    p_done = sub.add_parser("done", help="Mark next_task complete")
    p_done.add_argument("task_id", type=int)
    p_done.add_argument("--note", default="")
    p_done.add_argument("--evidence", nargs="*", default=[])

    p_block = sub.add_parser("block", help="Block current task")
    p_block.add_argument("task_id", type=int)
    p_block.add_argument("--reason", required=True)

    p_unblock = sub.add_parser("unblock", help="Unblock a task")
    p_unblock.add_argument("task_id", type=int)
    p_unblock.add_argument("--reason", required=True)

    p_skip = sub.add_parser("skip", help="Skip with mandatory reason")
    p_skip.add_argument("task_id", type=int)
    p_skip.add_argument("--reason", required=True)

    sub.add_parser("rebuild", help="Rebuild state from event log")
    sub.add_parser("validate", help="Read-only integrity report (state vs events)")
    sub.add_parser("check", help="Validate ledger invariants")
    sub.add_parser("status", help="Show current state")

    args = ap.parse_args(argv)
    if args.cmd is None:
        ap.print_help()
        return 1

    try:
        if args.cmd == "done":
            result = complete_task(args.task_id, note=args.note,
                                   evidence=args.evidence)
        elif args.cmd == "block":
            result = block_task(args.task_id, args.reason)
        elif args.cmd == "unblock":
            result = unblock_task(args.task_id, args.reason)
        elif args.cmd == "skip":
            result = skip_task(args.task_id, args.reason)
        elif args.cmd == "rebuild":
            result = rebuild_state()
        elif args.cmd == "validate":
            result = validate_state()
        elif args.cmd == "check":
            result = assert_ledger_invariants()
        elif args.cmd == "status":
            result = load_state()
        else:
            ap.print_help()
            return 1
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
        return 0
    except (PermissionError, ValueError, FileNotFoundError) as e:
        print(json.dumps({"ok": False, "error": str(e)}, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
