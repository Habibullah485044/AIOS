"""Test helpers: isolated audit DB + PEP grant minting for agent loop tests (T-03279)."""

from __future__ import annotations

import datetime as dt
import json
from contextlib import closing
from typing import Iterable

from aiosh_mcp import audit_client


def mint_grant(
    db_path: str,
    grant_id: str,
    tools: Iterable[str] = ("aios.agent_loop.start", "aios.fs.*"),
    expires_in: dt.timedelta = dt.timedelta(hours=1),
    single_use: bool = True,
) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    with closing(audit_client.open_db(db_path)) as conn:
        audit_client.ensure_pep_schema(conn)
        conn.execute(
            """INSERT INTO pep_grants (grant_id, issued_at, expires_at, issued_to, constitution_rev,
                                       scope_json, scope_hash, single_use)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (grant_id, now.isoformat(), (now + expires_in).isoformat(), "agent:test", "rev-test",
             json.dumps({"tools": list(tools)}), "hash-test", int(single_use)),
        )
        conn.commit()
    return grant_id


def revoke_grant(db_path: str, grant_id: str) -> None:
    with closing(audit_client.open_db(db_path)) as conn:
        conn.execute("UPDATE pep_grants SET revoked_at = ? WHERE grant_id = ?",
                     (audit_client.utcnow_iso(), grant_id))
        conn.commit()


def audit_tools(db_path: str) -> list[tuple[str, str]]:
    with closing(audit_client.open_db(db_path)) as conn:
        return [(r["tool"], r["outcome"]) for r in
                conn.execute("SELECT tool, outcome FROM audit_ring ORDER BY id")]


def verify_chain(db_path: str) -> dict:
    with closing(audit_client.open_db(db_path)) as conn:
        return audit_client.verify(conn)


class AllowAllGate:
    """In-memory gate double: redeems any token, allows every tool, records audit events.

    For tests of FSM/accounting behaviour only; gate behaviour itself is covered by
    test_agent_loop_core_service_security.py against the real PepCapabilityGate.
    """

    def __init__(self):
        self.events = []

    def redeem(self, grant_id, loop_id):
        self.events.append(("redeem", loop_id, grant_id))

    def tool_refusal(self, grant_id, tool_name):
        return None

    def audit(self, event, loop_id, grant_id, outcome, detail=None, args=None):
        self.events.append((event, loop_id, outcome))
