"""Redeem a PEP capability grant before a state-changing action (PoR invariant I-2; T-03429 F1).

Several MCP tools took a ``capability_token`` argument but only checked that it was a non-empty string, so any
string authorised the action. This module is the shared redeem-before-act gate for those tools. A token is a
``pep_grants`` grant id: it must exist, be unexpired and unrevoked, cover ``tool`` in ``scope.tools`` and, when single
use, not have been used. Redemption writes the grant's audit row (``audit_client.grant_redeem``).

The gate fails closed: any error (missing DB, schema, lock timeout, bad input) refuses the action.
"""

from __future__ import annotations

from contextlib import closing
from typing import Any, Dict, Optional

from aiosh_mcp import audit_client

#: Hard cap on a token's length; real grant ids are far shorter (mcp_server_core_policy uses the same bound).
MAX_TOKEN_CHARS = 512
CAPABILITY_ACTOR_ID = "agent:mcp@aiosh-mcp"


def _mask(text: str) -> str:
    try:
        from aiosh_mcp.agent_loop_data_model import mask_secrets
        return mask_secrets(text)
    except Exception:
        return "grant redemption refused"


def redeem_capability(token: Any, *, tool: str, command: str = "", args: Optional[Dict[str, Any]] = None,
                      target: Optional[str] = None, db_path: Optional[str] = None) -> Optional[str]:
    """Redeems ``token`` for ``tool``; returns None on success, otherwise a masked refusal reason."""
    if not isinstance(token, str) or not token.strip():
        return "capability token required"
    token = token.strip()
    if len(token) > MAX_TOKEN_CHARS or "\x00" in token:
        return "capability token is malformed"
    try:
        with closing(audit_client.open_db(db_path)) as conn:
            audit_client.ensure_pep_schema(conn)
            res = audit_client.grant_redeem(conn, token, actor_id=CAPABILITY_ACTOR_ID, tool=tool,
                                            command=command or tool, args=dict(args or {}, grant_id=token),
                                            target=target)
    except Exception as exc:  # fail closed: no redemption, no action
        return f"capability check unavailable ({type(exc).__name__})"
    if not res.get("ok"):
        return _mask(str(res.get("reason", "grant redemption refused")))[:300]
    return None
