"""Proof-of-Restraint capability gate for the Agent Loop Hardening surfaces (T-03279).

Replaces the "any non-empty string" token check with real PEP grant redemption
(PoR invariant I-2) against the shared audit ring, enforces the grant's
``scope.tools`` at the pre-execution policy gate (LOOPSERV-INV3), and writes one
audit row per consequential loop event (LOOPSERV-INV2).
"""

from __future__ import annotations

import datetime as dt
import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, List, Optional

from aiosh_mcp import audit_client
from aiosh_mcp.agent_loop_data_model import mask_secrets

#: Tool name a grant's ``scope.tools`` must cover to start a loop.
AGENT_LOOP_START_TOOL = "aios.agent_loop.start"
AGENT_LOOP_ACTOR_ID = "agent:mcp@aiosh-mcp/agent-loop"
BUSY_TIMEOUT_MS = 5000
#: Bounded wait for a locked audit DB on read (seconds).
HISTORY_DB_TIMEOUT_S = 5.0


class HistoryReadError(Exception):
    """The audit DB exists but cannot be opened or queried."""


class CapabilityRefused(Exception):
    """Raised when a capability token cannot be redeemed."""


class LoopIdTaken(Exception):
    """A start/init row for this loop_id already exists in the audit ring."""


class BudgetExhausted(Exception):
    """The grant's max_irreversible budget was spent when the ok row was about to be written (T-03330)."""

    def __init__(self, used: int, budget: int) -> None:
        super().__init__(f"irreversible budget exhausted: used {used} of {budget}")
        self.used = used
        self.budget = budget


_IRREVERSIBLE_USED_SQL = ("SELECT count(*) FROM audit_ring WHERE tool = 'aios.agent_loop.step' AND outcome = 'ok' "
                          "AND grant_token = ? AND json_extract(args_json, '$.irreversible') = 'True'")


#: Events that claim a loop_id for good; at most one may ever exist per id.
CLAIM_EVENTS = ("start", "init")
_CLAIM_TOOLS = tuple(f"aios.agent_loop.{e}" for e in CLAIM_EVENTS)


class PepCapabilityGate:
    """Production gate backed by the ``pep_grants`` table and ``audit_ring``."""

    def __init__(self, db_path: Optional[str] = None, busy_timeout_ms: Optional[int] = None) -> None:
        self._db_path = db_path
        if busy_timeout_ms is None:  # T-03310: fixed at construction from the process config
            from aiosh_mcp.agent_loop_config import process_config
            busy_timeout_ms = int(process_config()["config"]["db_busy_timeout_ms"])
        self._busy_timeout_ms = busy_timeout_ms

    def _busy_ms(self) -> int:
        return self._busy_timeout_ms

    def _open(self):
        conn = audit_client.open_db(self._db_path)
        # Bounded wait on a locked DB (T-03280) instead of failing or hanging.
        conn.execute(f"PRAGMA busy_timeout = {int(self._busy_ms())}")
        audit_client.ensure_pep_schema(conn)
        return conn

    def redeem(self, grant_id: str, loop_id: str) -> None:
        """Redeems ``grant_id`` for starting ``loop_id``; raises CapabilityRefused."""
        with closing(self._open()) as conn:
            res = audit_client.grant_redeem(
                conn,
                grant_id,
                actor_id=AGENT_LOOP_ACTOR_ID,
                tool=AGENT_LOOP_START_TOOL,
                command=f"agent_loop.start {loop_id}",
                args={"grant_id": grant_id, "loop_id": loop_id},
            )
        if not res.get("ok"):
            raise CapabilityRefused(mask_secrets(str(res.get("reason", "grant redemption refused"))))

    def tool_refusal(self, grant_id: str, tool_name: Optional[str],
                     target: Any = None) -> Optional[str]:
        """Returns a refusal reason if the bound grant no longer covers ``tool_name`` on ``target``.

        ``target`` is checked like ``audit_client.grant_check``: ``scope.networks`` for
        ``pentest.*`` / ``network.*`` tools when set, otherwise ``scope.paths``.
        """
        with closing(self._open()) as conn:
            grant = audit_client.load_grant(conn, grant_id)
        if grant is None:
            return f"grant {grant_id} unknown or revoked"
        try:
            expires = dt.datetime.fromisoformat(str(grant["expires_at"]).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return f"grant {grant_id} has malformed expires_at"
        if expires.tzinfo is None or expires < dt.datetime.now(dt.timezone.utc):
            return f"grant {grant_id} expired"
        scope = grant["scope"]
        if tool_name and not audit_client.tool_glob_match(tool_name, scope.get("tools") or []):
            return f"tool '{tool_name}' not in grant scope.tools"
        # T-03329: every target is checked, and a scoped grant with no checkable target fails closed.
        targets = [target] if isinstance(target, str) else list(target or [])
        networks = scope.get("networks") or []
        paths = scope.get("paths") or {}
        name = (tool_name or "").casefold()
        is_network = name in ("pentest", "network") or name.startswith(("pentest.", "network."))
        scoped = bool(networks) if is_network else bool(paths.get("allow") or paths.get("deny"))
        if tool_name and scoped and not targets:
            return f"no target in tool_args to check against grant scope.{'networks' if is_network else 'paths'}"
        for t in targets:
            if is_network and networks:
                if not audit_client.network_allowed(t, networks):
                    return f"target '{t}' blocked by grant scope.networks"
            elif not audit_client.path_allowed(t, paths or None):
                return f"target '{t}' blocked by grant scope.paths"
        return None

    def irreversible_used(self, grant_id: str) -> int:
        """ok irreversible loop steps already recorded for ``grant_id`` in the ring (T-03329).

        Counted from the durable ring, so the budget is per grant across loops, processes and restarts.
        """
        with closing(self._open()) as conn:
            row = conn.execute(_IRREVERSIBLE_USED_SQL, (grant_id,)).fetchone()
        return int(row[0] if row else 0)

    def irreversible_budget(self, grant_id: str) -> Optional[int]:
        """``scope.max_irreversible`` of the grant (None = no limit / unknown grant)."""
        with closing(self._open()) as conn:
            grant = audit_client.load_grant(conn, grant_id)
        value = (grant or {}).get("scope", {}).get("max_irreversible")
        if value is None or isinstance(value, bool):
            return None
        return max(0, int(value))

    @staticmethod
    def _claimed(conn, loop_id: str) -> bool:
        has_ring = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_ring'").fetchone()
        return bool(has_ring) and conn.execute(
            "SELECT 1 FROM audit_ring WHERE tool IN (?, ?) AND json_extract(args_json, '$.loop_id') = ? LIMIT 1",
            (*_CLAIM_TOOLS, loop_id)).fetchone() is not None

    def loop_id_used(self, loop_id: str) -> bool:
        """True if any process ever started or initialised ``loop_id`` (audit finding #2)."""
        with closing(self._open()) as conn:
            return self._claimed(conn, loop_id)

    def audit(
        self,
        event: str,
        loop_id: str,
        grant_id: Optional[str],
        outcome: str,
        detail: Optional[str] = None,
        args: Optional[Dict[str, Any]] = None,
        classification: Optional[Dict[str, Any]] = None,
        budget_guard: Optional[int] = None,
    ) -> None:
        """Appends one hash-chained audit row for a loop event.

        ``classification`` (T-03326) carries the constitution classifier result for steps:
        real ``c_flags``, ``policy_revision`` and the ``classify_*`` columns, as in ``_dispatch``.
        """
        payload = {"loop_id": loop_id, **(args or {})}
        with closing(self._open()) as conn:
            if event in CLAIM_EVENTS:
                # Check-and-claim under one write lock so two processes cannot both start the same id.
                conn.execute("BEGIN IMMEDIATE")
                if self._claimed(conn, loop_id):
                    conn.rollback()
                    raise LoopIdTaken(f"loop_id '{loop_id}' was already started")
            elif budget_guard is not None:
                # Re-check the per-grant budget and write the ok row under one write lock (T-03330),
                # so concurrent processes sharing a multi-use grant cannot overspend it.
                conn.execute("BEGIN IMMEDIATE")
                used = int(conn.execute(_IRREVERSIBLE_USED_SQL, (grant_id,)).fetchone()[0])
                if used >= budget_guard:
                    conn.rollback()
                    raise BudgetExhausted(used, budget_guard)
            audit_client.write_audit_row(conn, {
                "ts": audit_client.utcnow_iso(),
                "actor": "agent",
                "actor_id": AGENT_LOOP_ACTOR_ID,
                "tool": f"aios.agent_loop.{event}",
                "command": f"agent_loop.{event} {loop_id}",
                "args": {k: mask_secrets(str(v)) for k, v in payload.items()},
                "target": None,
                "outcome": outcome,
                "outcome_detail": mask_secrets(detail) if detail else None,
                "constitution_rev": None,
                "grant_token": grant_id,
                "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True},
                **(classification or {}),
            })


def read_loop_history(db_path: Optional[str], loop_id: str, limit: int,
                      after_id: int = 0) -> List[Dict[str, Any]]:
    """Read-only ``aios.agent_loop.*`` audit rows for ``loop_id``, oldest first (T-03296).

    Never creates or migrates the DB: a missing file or table yields ``[]``.
    """
    path = Path(db_path or audit_client.default_db_path())
    if not path.is_file():
        return []
    try:
        conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, timeout=HISTORY_DB_TIMEOUT_S)
    except sqlite3.Error as exc:
        raise HistoryReadError(f"cannot open audit DB: {exc}") from exc
    try:
        conn.row_factory = sqlite3.Row
        has_ring = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_ring'").fetchone()
        rows = conn.execute(
            """SELECT id, ts, tool, outcome, outcome_detail, args_json,
                      classify_overall_verdict, classify_rule_ids_json FROM audit_ring
               WHERE substr(tool, 1, 16) = 'aios.agent_loop.' AND json_extract(args_json, '$.loop_id') = ?
                 AND id > ?
               ORDER BY id LIMIT ?""",
            (loop_id, after_id, limit),
        ).fetchall() if has_ring else []
    except sqlite3.Error as exc:
        raise HistoryReadError(f"cannot read audit DB: {exc}") from exc
    finally:
        conn.close()
    return [{"id": r["id"], "ts": r["ts"], "tool": r["tool"], "outcome": r["outcome"],
             "outcome_detail": r["outcome_detail"], "args": json.loads(r["args_json"]),
             # Constitution verdict recorded on step rows since T-03326 (None on other events / older rows).
             "verdict": r["classify_overall_verdict"],
             "rule_ids": json.loads(r["classify_rule_ids_json"]) if r["classify_rule_ids_json"] else []}
            for r in rows]
