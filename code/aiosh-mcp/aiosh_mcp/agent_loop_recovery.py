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


def _runs(conn: sqlite3.Connection) -> Dict[str, Dict[str, Any]]:
    """Groups trusted agent-loop rows by run_id (rows without a run_id predate #420 and are skipped)."""
    rows = conn.execute(
        "SELECT id, ts, tool, outcome, grant_token, json_extract(args_json, '$.loop_id') AS loop_id, "
        "json_extract(args_json, '$.run_id') AS run_id, json_extract(args_json, '$.step_index') AS step_index, "
        "json_extract(args_json, '$.irreversible') AS irreversible "
        "FROM audit_ring WHERE substr(tool, 1, 16) = ? AND actor_id = ? ORDER BY id",
        (_PREFIX, AGENT_LOOP_ACTOR_ID))
    runs: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        if not r["run_id"]:
            continue
        run = runs.setdefault(r["run_id"], {"run_id": r["run_id"], "loop_ids": set(), "starts": 0, "steps": [],
                                            "terminal": [], "after_terminal": 0, "last_ts": None, "grant": None,
                                            "irreversible_ok": 0})
        event = r["tool"][len(_PREFIX):]
        run["loop_ids"].add(r["loop_id"])
        run["last_ts"] = r["ts"]
        if run["terminal"]:
            run["after_terminal"] += 1
        if event in ("start", "init"):
            run["starts"] += 1
            run["grant"] = r["grant_token"]
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
                  live_runs: Iterable[str] = ()) -> Dict[str, Any]:
    """Read-only per-run report (spec §2); never creates the DB (LOOPREC-INV3)."""
    live = set(live_runs)
    path = Path(db_path or audit_client.default_db_path())
    report: Dict[str, Any] = {"runs": 0, "open": 0, "orphaned": [], "problems": [], "chain_ok": True,
                              "ok": True, "truncated": False}
    if not path.is_file():
        return report
    conn = _ro_connect(path)
    try:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_ring'").fetchone():
            return report
        runs = _runs(conn)
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

    now = dt.datetime.now(dt.timezone.utc)
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
            last = _parse_ts(run["last_ts"])
            age = (now - last).total_seconds() if last else float("inf")
            if run["run_id"] not in live and age > grace_s:
                report["orphaned"].append({"loop_id": loop_id, "run_id": run["run_id"],
                                           "last_step_index": max(run["steps"]) if run["steps"] else None,
                                           "last_ts": run["last_ts"]})
    for lid, rids in by_loop.items():
        if len(rids) > 1:
            report["problems"].append({"loop_id": lid, "run_id": None, "kind": "run_id_mixed",
                                       "detail": f"{len(rids)} run_ids share loop_id"})
    report["runs"] = len(runs)
    for key in ("orphaned", "problems"):
        if len(report[key]) > MAX_LISTED_RUNS:
            report[key] = report[key][:MAX_LISTED_RUNS]
            report["truncated"] = True
    report["ok"] = not report["problems"] and not report["orphaned"] and report["chain_ok"]
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
    orphans = validate_ring(db_path, grace_s, live)["orphaned"]
    with closing(audit_client.open_db(db_path)) as conn:
        audit_client.ensure_pep_schema(conn)
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
            if closed:
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
    return {"recovered": recovered, "skipped_live": len(live)}
