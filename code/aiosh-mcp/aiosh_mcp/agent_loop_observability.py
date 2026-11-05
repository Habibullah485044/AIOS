"""Agent Loop Hardening observability (T-03335 scaffold / T-03336 impl).

Spec: docs/tasks/evidence/T-03334-spec.md. Ring-derived metrics (cross-process, durable),
health classification and the module logger; LOOPOBS-INV1..LOOPOBS-INV3.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

#: Library logger: adds no handlers (the application configures logging).
logger = logging.getLogger("aiosh_mcp.agent_loop")

LOOPOBS_ERR_READ = "LOOPOBS_ERR_READ"
DEFAULT_WINDOW = 10_000
MAX_WINDOW = 100_000
REFUSAL_REASONS = ("constitution", "irreversible_budget", "scope", "caller", "target", "gate_unavailable", "other")
HEALTH_STATES = ("ok", "degraded", "failing")


class ObservabilityReadError(Exception):
    """The audit DB exists but cannot be opened or queried."""


def classify_refusal(outcome_detail: Optional[str]) -> str:
    """Maps a refused step's ``outcome_detail`` onto one of ``REFUSAL_REASONS``."""
    d = outcome_detail or ""
    if "LOOPPOL_ERR_CONSTITUTION" in d:
        return "constitution"
    if "LOOPPOL_ERR_IRREVERSIBLE_BUDGET" in d:
        return "irreversible_budget"
    if "LOOPPOL_ERR_TARGET" in d:
        return "target"
    if "GATE_UNAVAILABLE" in d:
        return "gate_unavailable"
    if "caller policy verdict" in d:
        return "caller"
    if any(k in d for k in ("grant scope", "not in grant", "blocked by grant", "no target in tool_args",
                            "unknown or revoked", "expired")):
        return "scope"
    return "other"


def _pct(values: List[float], q: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    k = max(0, min(len(ordered) - 1, int(round(q * (len(ordered) - 1)))))
    return round(ordered[k], 3)


def _empty_metrics() -> Dict[str, Any]:
    return {"window": {"rows": 0, "first_id": None, "last_id": None, "first_ts": None, "last_ts": None},
            "events": {e: 0 for e in ("start", "step", "abort", "complete", "timeout", "init", "config")},
            "steps": {"ok": 0, "refused": 0, "irreversible_ok": 0,
                      "duration_ms": {"count": 0, "p50": None, "p95": None, "max": None}},
            "refusals": {r: 0 for r in REFUSAL_REASONS},
            "irreversible_by_grant": [],
            "degraded_config_rows": 0}


def ring_metrics(db_path: Optional[str] = None, window: int = DEFAULT_WINDOW) -> Dict[str, Any]:
    """Read-only aggregates over the newest ``window`` agent-loop audit rows (spec §2)."""
    if isinstance(window, bool) or not isinstance(window, int) or not (1 <= window <= MAX_WINDOW):
        raise ValueError(f"window must be an int in [1, {MAX_WINDOW}]")
    from aiosh_mcp import audit_client
    out = _empty_metrics()
    path = Path(db_path or audit_client.default_db_path())
    if not path.is_file():
        return out
    try:
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=5.0)
    except sqlite3.Error as exc:
        raise ObservabilityReadError(f"{LOOPOBS_ERR_READ}: cannot open audit DB: {exc}") from exc
    try:
        if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_ring'").fetchone():
            return out
        # substr(), not LIKE: '_' is a LIKE wildcard and 'aios.agent_loop.' contains one.
        rows = conn.execute(
            "SELECT id, ts, tool, outcome, outcome_detail, args_json, grant_token FROM audit_ring "
            "WHERE substr(tool, 1, 16) = 'aios.agent_loop.' ORDER BY id DESC LIMIT ?", (window,)).fetchall()
    except sqlite3.Error as exc:
        raise ObservabilityReadError(f"{LOOPOBS_ERR_READ}: cannot read audit DB: {exc}") from exc
    finally:
        conn.close()
    if not rows:
        return out
    rows.reverse()
    out["window"] = {"rows": len(rows), "first_id": rows[0][0], "last_id": rows[-1][0],
                     "first_ts": rows[0][1], "last_ts": rows[-1][1]}
    durations: List[float] = []
    by_grant: Dict[str, int] = {}
    for _id, _ts, tool, outcome, detail, args_json, grant in rows:
        event = tool[len("aios.agent_loop."):]
        if event in out["events"]:
            out["events"][event] += 1
        if event == "config" and outcome == "degraded":
            out["degraded_config_rows"] += 1
        if event != "step":
            continue
        try:
            args = json.loads(args_json or "{}")
        except ValueError:
            args = {}
        if outcome == "ok":
            out["steps"]["ok"] += 1
            if str(args.get("irreversible")) == "True":
                out["steps"]["irreversible_ok"] += 1
                if grant:
                    key = hashlib.sha256(grant.encode()).hexdigest()[:12]   # grant ids are bearer tokens
                    by_grant[key] = by_grant.get(key, 0) + 1
        elif outcome == "refused":
            out["steps"]["refused"] += 1
            out["refusals"][classify_refusal(detail)] += 1
        try:
            durations.append(float(args["duration_ms"]))
        except (KeyError, TypeError, ValueError):
            pass   # rows written before T-03336 carry no measured duration
    out["steps"]["duration_ms"] = {"count": len(durations), "p50": _pct(durations, 0.50),
                                   "p95": _pct(durations, 0.95),
                                   "max": round(max(durations), 3) if durations else None}
    out["irreversible_by_grant"] = [{"grant_hash": k, "ok": v} for k, v in sorted(by_grant.items())]
    return out


def health(ring: Dict[str, Any], live: Optional[Dict[str, Any]] = None, config_degraded: bool = False) -> str:
    """``ok`` | ``degraded`` | ``failing`` (spec §5)."""
    counters = (live or {}).get("counters", {})
    if ring.get("error") or counters.get("audit_failures", 0) > 0:
        return "failing"
    if (config_degraded or counters.get("gate_unavailable", 0) > 0 or ring.get("degraded_config_rows", 0) > 0
            or ring.get("refusals", {}).get("gate_unavailable", 0) > 0):
        return "degraded"
    return "ok"


def log_event(event: str, loop_id: str, run_id: Optional[str], outcome: str, reason: Optional[str] = None,
              level: int = logging.INFO) -> None:
    """One masked structured log line per consequential action (never grant ids or args, LOOPOBS-INV1)."""
    if not logger.isEnabledFor(level):
        return
    from aiosh_mcp.agent_loop_data_model import mask_secrets
    fields = {"event": event, "loop_id": loop_id, "run_id": run_id, "outcome": outcome}
    if reason:
        fields["reason"] = mask_secrets(reason)[:200]
    msg = f"agent_loop {event} loop={loop_id} run={run_id} outcome={outcome}" + (
        f" reason={fields['reason']}" if reason else "")
    logger.log(level, mask_secrets(msg), extra={"agent_loop": fields})
