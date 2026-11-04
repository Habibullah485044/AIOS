"""Proof-of-Restraint capability gate for the Agent Loop Hardening surfaces (T-03279).

Replaces the "any non-empty string" token check with real PEP grant redemption
(PoR invariant I-2) against the shared audit ring, enforces the grant's
``scope.tools`` at the pre-execution policy gate (LOOPSERV-INV3), and writes one
audit row per consequential loop event (LOOPSERV-INV2).
"""

from __future__ import annotations

import datetime as dt
from contextlib import closing
from typing import Any, Dict, Optional

from aiosh_mcp import audit_client
from aiosh_mcp.agent_loop_data_model import mask_secrets

#: Tool name a grant's ``scope.tools`` must cover to start a loop.
AGENT_LOOP_START_TOOL = "aios.agent_loop.start"
AGENT_LOOP_ACTOR_ID = "agent:mcp@aiosh-mcp/agent-loop"


class CapabilityRefused(Exception):
    """Raised when a capability token cannot be redeemed."""


class PepCapabilityGate:
    """Production gate backed by the ``pep_grants`` table and ``audit_ring``."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = db_path

    def _open(self):
        conn = audit_client.open_db(self._db_path)
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

    def tool_refusal(self, grant_id: str, tool_name: Optional[str]) -> Optional[str]:
        """Returns a refusal reason if the bound grant no longer covers ``tool_name``."""
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
        if tool_name and not audit_client.tool_glob_match(tool_name, grant["scope"].get("tools") or []):
            return f"tool '{tool_name}' not in grant scope.tools"
        return None

    def audit(
        self,
        event: str,
        loop_id: str,
        grant_id: Optional[str],
        outcome: str,
        detail: Optional[str] = None,
        args: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Appends one hash-chained audit row for a loop event."""
        payload = {"loop_id": loop_id, **(args or {})}
        with closing(self._open()) as conn:
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
            })
