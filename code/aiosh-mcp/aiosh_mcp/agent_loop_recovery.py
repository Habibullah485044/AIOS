"""Agent Loop Hardening recovery & validation (T-03355 scaffold / T-03356 impl).

Spec: docs/tasks/evidence/T-03354-spec.md. Validates runs reconstructed from the audit ring
and honestly closes runs orphaned by a crash (LOOPREC-INV1..LOOPREC-INV3).
"""

from __future__ import annotations

import datetime as dt
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from aiosh_mcp import audit_client
from aiosh_mcp.agent_loop_data_model import mask_secrets
from aiosh_mcp.agent_loop_gate import AGENT_LOOP_ACTOR_ID

RECOVER_TOOL = "aios.agent_loop.recover"
LOOPREC_ERR_READ = "LOOPREC_ERR_READ"
#: Same value as agent_loop_service.LOOPSERV_ERR_UNAUTHORIZED (kept local to avoid an import cycle).
LOOPSERV_ERR_UNAUTHORIZED = "LOOPSERV_ERR_UNAUTHORIZED"
TERMINAL_EVENTS = ("abort", "complete", "timeout", "failed", "recovered")
DEFAULT_GRACE_S = 900
MAX_LISTED_RUNS = 1000
#: Newest agent-loop rows scanned per validation (T-03359 #4: bounded cost for a tokenless call).
DEFAULT_WINDOW_ROWS = 50_000
#: A run is only recoverable once its own total timeout has passed (it can no longer legitimately step);
#: runs whose start row lacks the value use the LoopConfig maximum (T-03359 #1).
MAX_TOTAL_TIMEOUT_S = 1800.0
TIMEOUT_MARGIN_S = 1.0


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)
PROBLEM_KINDS = ("rows_after_terminal", "duplicate_start", "step_index_gap", "run_id_mixed",
                 "budget_exceeded", "missing_start")


class RecoveryError(Exception):
    """Recovery refused or failed; ``code`` is a documented error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


_PREFIX = "aios.agent_loop."


def _parse_ts(ts: Optional[str]) -> Optional[dt.datetime]:
    try:
        parsed = dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except (TypeError, ValueError):
        return None


def _ro_connect(path: Path) -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error as exc:
        raise RecoveryError(LOOPREC_ERR_READ, f"cannot open audit DB: {exc}") from exc
    conn.row_factory = sqlite3.Row
    return conn


def _runs(conn: sqlite3.Connection, window: int = DEFAULT_WINDOW_ROWS) -> Dict[str, Dict[str, Any]]:
    """Groups trusted agent-loop rows by run_id over the newest ``window`` rows (rows without a run_id
    predate #420 and are skipped)."""
    rows = conn.execute(
        "SELECT * FROM (SELECT id, ts, tool, outcome, grant_token, json_extract(args_json, '$.loop_id') AS loop_id, "
        "json_extract(args_json, '$.run_id') AS run_id, json_extract(args_json, '$.step_index') AS step_index, "
        "json_extract(args_json, '$.irreversible') AS irreversible, "
        "json_extract(args_json, '$.total_timeout_ms') AS total_timeout_ms "
        "FROM audit_ring WHERE substr(tool, 1, 16) = ? AND actor_id = ? ORDER BY id DESC LIMIT ?) ORDER BY id",
        (_PREFIX, AGENT_LOOP_ACTOR_ID, window))
    runs: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        if not r["run_id"]:
            continue
        run = runs.setdefault(r["run_id"], {"run_id": r["run_id"], "loop_ids": set(), "starts": 0, "steps": [],
                                            "terminal": [], "after_terminal": 0, "last_ts": None, "grant": None,
                                            "irreversible_ok": 0, "last_id": None, "start_ts": None,
                                            "timeout_s": MAX_TOTAL_TIMEOUT_S})
        event = r["tool"][len(_PREFIX):]
        run["loop_ids"].add(r["loop_id"])
        run["last_ts"] = r["ts"]
        run["last_id"] = r["id"]
        if run["terminal"]:
            run["after_terminal"] += 1
        if event in ("start", "init"):
            run["starts"] += 1
            run["grant"] = r["grant_token"]
            run["start_ts"] = r["ts"]
            try:
                run["timeout_s"] = min(MAX_TOTAL_TIMEOUT_S, float(r["total_timeout_ms"]) / 1000.0)
            except (TypeError, ValueError):
                pass
        elif event == "step":
            try:
                run["steps"].append(int(r["step_index"]))
            except (TypeError, ValueError):
                run["steps"].append(-1)
            if r["outcome"] == "ok" and str(r["irreversible"]) == "True":
                run["irreversible_ok"] += 1
        if event in TERMINAL_EVENTS:
            run["terminal"].append(event)
    return runs


def validate_ring(db_path: Optional[str] = None, grace_s: float = DEFAULT_GRACE_S,
                  live_runs: Iterable[str] = (), verify_chain: bool = False, window: int = DEFAULT_WINDOW_ROWS,
                  max_listed: Optional[int] = MAX_LISTED_RUNS) -> Dict[str, Any]:
    """Read-only per-run report (spec §2); never creates the DB (LOOPREC-INV3).

    T-03359: scans the newest ``window`` rows; the hash-chain check is opt-in (``verify_chain``);
    an open run is *orphaned* only when it is not live here, idle for ``grace_s`` **and** past its
    own total timeout, i.e. when no process could still legitimately be stepping it.
    """
    live = set(live_runs)
    path = Path(db_path or audit_client.default_db_path())
    report: Dict[str, Any] = {"runs": 0, "open": 0, "orphaned": [], "problems": [], "chain_ok": None,
                              "ok": True, "truncated": False, "skipped_live": 0}
    if not path.is_file():
        return report
    conn = _ro_connect(path)
    try:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_ring'").fetchone():
            return report
        runs = _runs(conn, window)
        if verify_chain:
            report["chain_ok"] = bool(audit_client.verify_live(conn)["ok"])
        budgets: Dict[str, Optional[int]] = {}
        has_grants = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='pep_grants'").fetchone() is not None
        per_grant: Dict[str, int] = {}
        for run in runs.values():
            if run["grant"]:
                per_grant[run["grant"]] = per_grant.get(run["grant"], 0) + run["irreversible_ok"]
        for grant, used in per_grant.items():
            if has_grants and grant not in budgets:
                g = audit_client.load_grant(conn, grant)
                value = (g or {}).get("scope", {}).get("max_irreversible")
                budgets[grant] = None if value is None or isinstance(value, bool) else int(value)
            if budgets.get(grant) is not None and used > budgets[grant]:
                report["problems"].append({"loop_id": None, "run_id": None, "kind": "budget_exceeded",
                                           "detail": f"grant {_grant_hash(grant)} used {used} of {budgets[grant]}"})
    except sqlite3.Error as exc:
        raise RecoveryError(LOOPREC_ERR_READ, f"cannot read audit DB: {exc}") from exc
    finally:
        conn.close()

    now = _now()
    by_loop: Dict[str, set] = {}
    for run in runs.values():
        loop_id = sorted(x for x in run["loop_ids"] if x)[0] if any(run["loop_ids"]) else None
        for lid in run["loop_ids"]:
            by_loop.setdefault(lid, set()).add(run["run_id"])

        def problem(kind: str, detail: str) -> None:
            report["problems"].append({"loop_id": loop_id, "run_id": run["run_id"], "kind": kind, "detail": detail})

        if run["starts"] == 0:
            problem("missing_start", "run has rows but no start/init row")
        elif run["starts"] > 1:
            problem("duplicate_start", f"{run['starts']} start rows")
        if run["steps"] != list(range(len(run["steps"]))):
            problem("step_index_gap", f"step indices {run['steps'][:10]}")
        if run["after_terminal"]:
            problem("rows_after_terminal", f"{run['after_terminal']} row(s) after {run['terminal'][0]}")
        if not run["terminal"]:
            report["open"] += 1
            if run["run_id"] in live:
                report["skipped_live"] += 1
                continue
            last = _parse_ts(run["last_ts"])
            started = _parse_ts(run["start_ts"])
            idle = (now - last).total_seconds() if last else float("inf")
            running_for = (now - started).total_seconds() if started else float("inf")
            if idle > grace_s and running_for > run["timeout_s"] + TIMEOUT_MARGIN_S:
                report["orphaned"].append({"loop_id": loop_id, "run_id": run["run_id"],
                                           "last_step_index": max(run["steps"]) if run["steps"] else None,
                                           "last_ts": run["last_ts"], "last_id": run["last_id"]})
    for lid, rids in by_loop.items():
        if len(rids) > 1:
            report["problems"].append({"loop_id": lid, "run_id": None, "kind": "run_id_mixed",
                                       "detail": f"{len(rids)} run_ids share loop_id"})
    report["runs"] = len(runs)
    for key in ("orphaned", "problems"):
        if max_listed is not None and len(report[key]) > max_listed:
            report[key] = report[key][:max_listed]
            report["truncated"] = True
    report["ok"] = not report["problems"] and not report["orphaned"] and report["chain_ok"] is not False
    return report


def _grant_hash(grant: str) -> str:
    import hashlib
    return hashlib.sha256(grant.encode()).hexdigest()[:12]   # grant ids are bearer tokens


def recover_orphans(db_path: Optional[str], capability_token: str, grace_s: float = DEFAULT_GRACE_S,
                    live_runs: Iterable[str] = ()) -> Dict[str, Any]:
    """Grant-gated, idempotent: one ``aios.agent_loop.recovered`` row per orphaned run (spec §3)."""
    token = (capability_token or "").strip()
    if not token:
        raise RecoveryError(LOOPSERV_ERR_UNAUTHORIZED, "capability token required to recover runs (PoR I-2)")
    live = list(live_runs)
    found = validate_ring(db_path, grace_s, live, max_listed=None)    # recovery is not capped at the listing limit
    orphans = found["orphaned"]
    with closing(audit_client.open_db(db_path)) as conn:
        audit_client.ensure_pep_schema(conn)
        # T-03359 #3: a broad glob (aios.agent_loop.*, *) must not authorise closing other loops' runs.
        grant = audit_client.load_grant(conn, token)
        if grant is None or RECOVER_TOOL not in (grant.get("scope", {}).get("tools") or []):
            raise RecoveryError(LOOPSERV_ERR_UNAUTHORIZED,
                                f"grant must list {RECOVER_TOOL} explicitly in scope.tools (PoR I-2)")
        res = audit_client.grant_redeem(conn, token, actor_id=AGENT_LOOP_ACTOR_ID, tool=RECOVER_TOOL,
                                        command="agent_loop.recover", args={"orphans": len(orphans)})
        if not res.get("ok"):
            raise RecoveryError(LOOPSERV_ERR_UNAUTHORIZED, mask_secrets(str(res.get("reason", "refused"))))
        recovered: List[Dict[str, Any]] = []
        for o in orphans:
            conn.execute("BEGIN IMMEDIATE")
            # Re-check under the write lock: another recovery or a late terminal row may have closed it.
            closed = conn.execute(
                "SELECT 1 FROM audit_ring WHERE actor_id = ? AND json_extract(args_json, '$.run_id') = ? AND tool IN "
                f"({','.join('?' * len(TERMINAL_EVENTS))}) LIMIT 1",
                (AGENT_LOOP_ACTOR_ID, o["run_id"], *[_PREFIX + e for e in TERMINAL_EVENTS])).fetchone()
            newest = conn.execute(
                "SELECT max(id) FROM audit_ring WHERE actor_id = ? AND json_extract(args_json, '$.run_id') = ?",
                (AGENT_LOOP_ACTOR_ID, o["run_id"])).fetchone()[0]
            # T-03359 #1: anything written for the run since validation means it is alive: leave it.
            if closed or newest != o["last_id"]:
                conn.rollback()
                continue
            audit_client.write_audit_row(conn, {
                "ts": audit_client.utcnow_iso(), "actor": "agent", "actor_id": AGENT_LOOP_ACTOR_ID,
                "tool": _PREFIX + "recovered", "command": f"agent_loop.recovered {o['loop_id']}",
                "args": {"loop_id": o["loop_id"], "run_id": o["run_id"],
                         "last_step_index": str(o["last_step_index"]), "last_ts": o["last_ts"]},
                "target": None, "outcome": "abandoned",
                "outcome_detail": "run had no terminal row (process ended); closed by recovery",
                "constitution_rev": None, "grant_token": token,
                "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True},
            })
            recovered.append(o)
    return {"recovered": recovered, "skipped_live": found["skipped_live"]}
