"""Agent Loop Hardening observability (T-03335 scaffold / T-03336 impl).

Spec: docs/tasks/evidence/T-03334-spec.md. Ring-derived metrics (cross-process, durable),
health classification and the module logger; LOOPOBS-INV1..LOOPOBS-INV3.
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

#: Library logger: adds no handlers (the application configures logging).
logger = logging.getLogger("aiosh_mcp.agent_loop")

LOOPOBS_ERR_READ = "LOOPOBS_ERR_READ"
DEFAULT_WINDOW = 10_000
MAX_WINDOW = 100_000
REFUSAL_REASONS = ("constitution", "irreversible_budget", "scope", "caller", "target", "gate_unavailable", "other")
HEALTH_STATES = ("ok", "degraded", "failing")
#: Only rows written by the agent-loop gate are counted (T-03339 #3): other ring writers are ignored.
TRUSTED_ACTOR_ID = "agent:mcp@aiosh-mcp/agent-loop"
#: Per-grant irreversible list is capped (top N by count) so one call cannot return 100k entries.
MAX_GRANT_ENTRIES = 20
#: args_json longer than this is not inspected for duration/irreversible/refusal fields.
MAX_ARGS_JSON_SCAN = 8192
#: Wall-clock budget for one metrics query (T-03340). Enforced *inside* SQLite via a progress handler,
#: so it also stops a query whose MCP call already timed out and abandoned its worker thread.
DEFAULT_QUERY_DEADLINE_S = 10.0


class ObservabilityReadError(Exception):
    """The audit DB exists but cannot be opened or queried."""


_REFUSAL_PREFIXES = (
    ("LOOPPOL_ERR_CONSTITUTION", "constitution"),
    ("LOOPPOL_ERR_IRREVERSIBLE_BUDGET", "irreversible_budget"),
    ("LOOPPOL_ERR_TARGET", "target"),
    ("LOOPSERV_ERR_GATE_UNAVAILABLE", "gate_unavailable"),
    ("caller policy verdict", "caller"),
    ("tool '", "scope"), ("target '", "scope"), ("grant ", "scope"), ("no target in tool_args", "scope"),
)
_REFUSED_PREFIX = "LOOPSERV_ERR_POLICY_REFUSED: Policy evaluation refused tool invocation: "


def classify_refusal(outcome_detail: Optional[str]) -> str:
    """Fallback for rows without ``refusal_reason`` (pre-T-03339). Prefix match on the refusal itself,
    never a substring search: caller-chosen targets can contain any code text (T-03339 #2)."""
    d = outcome_detail or ""
    if d.startswith(_REFUSED_PREFIX):
        d = d[len(_REFUSED_PREFIX):]
    for prefix, reason in _REFUSAL_PREFIXES:
        if d.startswith(prefix):
            return reason
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


def ring_metrics(db_path: Optional[str] = None, window: int = DEFAULT_WINDOW,
                 deadline_s: float = DEFAULT_QUERY_DEADLINE_S) -> Dict[str, Any]:
    """Read-only aggregates over the newest ``window`` agent-loop audit rows (spec §2).

    Streams rows (constant memory apart from the duration list) and aborts with
    ``ObservabilityReadError`` once ``deadline_s`` is exceeded (T-03340).
    """
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
        # Streamed and extracted in SQLite (T-03339 #3): no fetchall() of whole args blobs, and only rows
        # written by the agent-loop gate's actor are trusted.
        stop_at = time.monotonic() + deadline_s
        conn.set_progress_handler(lambda: 1 if time.monotonic() > stop_at else 0, 10_000)
        cursor = conn.execute(
            "SELECT id, ts, tool, outcome, outcome_detail, grant_token, "
            "  CASE WHEN length(args_json) <= ? THEN json_extract(args_json, '$.irreversible') END, "
            "  CASE WHEN length(args_json) <= ? THEN json_extract(args_json, '$.duration_ms') END, "
            "  CASE WHEN length(args_json) <= ? THEN json_extract(args_json, '$.refusal_reason') END "
            "FROM audit_ring WHERE substr(tool, 1, 16) = 'aios.agent_loop.' AND actor_id = ? "
            "ORDER BY id DESC LIMIT ?",
            (MAX_ARGS_JSON_SCAN, MAX_ARGS_JSON_SCAN, MAX_ARGS_JSON_SCAN, TRUSTED_ACTOR_ID, window))
        durations: List[float] = []
        by_grant: Dict[str, int] = {}
        n = 0
        newest = oldest = None
        for row in cursor:   # streamed newest -> oldest; aggregates are order-independent
            _id, ts, tool, outcome, detail, grant, irreversible, duration, refusal_reason = row
            n += 1
            newest = newest or (_id, ts)
            oldest = (_id, ts)
            event = tool[len("aios.agent_loop."):]
            if event in out["events"]:
                out["events"][event] += 1
            if event == "config" and outcome == "degraded":
                out["degraded_config_rows"] += 1
            if event != "step":
                continue
            if outcome == "ok":
                out["steps"]["ok"] += 1
                if str(irreversible) == "True":
                    out["steps"]["irreversible_ok"] += 1
                    if grant:
                        key = hashlib.sha256(grant.encode()).hexdigest()[:12]   # grant ids are bearer tokens
                        by_grant[key] = by_grant.get(key, 0) + 1
            elif outcome == "refused":
                out["steps"]["refused"] += 1
                reason = refusal_reason if refusal_reason in REFUSAL_REASONS else classify_refusal(detail)
                out["refusals"][reason] += 1
            try:
                durations.append(float(duration))
            except (TypeError, ValueError):
                pass   # rows written before T-03336 carry no measured duration
    except sqlite3.OperationalError as exc:
        if "interrupted" in str(exc):
            raise ObservabilityReadError(
                f"{LOOPOBS_ERR_READ}: metrics query exceeded its {deadline_s}s budget; use a smaller window") from exc
        raise ObservabilityReadError(f"{LOOPOBS_ERR_READ}: cannot read audit DB: {exc}") from exc
    except sqlite3.Error as exc:
        raise ObservabilityReadError(f"{LOOPOBS_ERR_READ}: cannot read audit DB: {exc}") from exc
    finally:
        conn.close()
    if not n:
        return out
    out["window"] = {"rows": n, "first_id": oldest[0], "last_id": newest[0], "first_ts": oldest[1], "last_ts": newest[1]}
    out["steps"]["duration_ms"] = {"count": len(durations), "p50": _pct(durations, 0.50),
                                   "p95": _pct(durations, 0.95),
                                   "max": round(max(durations), 3) if durations else None}
    top = sorted(by_grant.items(), key=lambda kv: (-kv[1], kv[0]))[:MAX_GRANT_ENTRIES]
    out["irreversible_by_grant"] = [{"grant_hash": k, "ok": v} for k, v in top]
    out["irreversible_grants_total"] = len(by_grant)
    return out


def health(ring: Dict[str, Any], live: Optional[Dict[str, Any]] = None, config_degraded: bool = False) -> str:
    """``ok`` | ``degraded`` | ``failing`` (spec §5)."""
    counters = (live or {}).get("counters", {})
    if ring.get("error") or counters.get("audit_failures", 0) > 0:
        return "failing"
    if (config_degraded or counters.get("gate_unavailable", 0) > 0 or ring.get("degraded_config_rows", 0) > 0
            or ring.get("orphaned_runs", 0) > 0
            or ring.get("refusals", {}).get("gate_unavailable", 0) > 0):
        return "degraded"
    return "ok"


def log_event(event: str, loop_id: str, run_id: Optional[str], outcome: str, reason: Optional[str] = None,
              level: int = logging.INFO) -> None:
    """One masked structured log line per consequential action (never grant ids or args, LOOPOBS-INV1)."""
    try:
        if not logger.isEnabledFor(level):
            return
    except Exception:
        return
    from aiosh_mcp.agent_loop_data_model import mask_secrets

    def clean(v: Any) -> Any:  # no control characters in log lines (T-03339 #2: log injection)
        return None if v is None else "".join(ch if ch.isprintable() else repr(ch)[1:-1] for ch in str(v))

    fields = {"event": clean(event), "loop_id": clean(loop_id), "run_id": clean(run_id), "outcome": clean(outcome)}
    if reason:
        fields["reason"] = clean(mask_secrets(reason)[:200])
    msg = f"agent_loop {fields['event']} loop={fields['loop_id']} run={fields['run_id']} outcome={fields['outcome']}" + (
        f" reason={fields['reason']}" if reason else "")
    try:
        logger.log(level, mask_secrets(msg), extra={"agent_loop": fields})
    except Exception:  # T-03340: a broken log handler must never break a loop step
        pass
