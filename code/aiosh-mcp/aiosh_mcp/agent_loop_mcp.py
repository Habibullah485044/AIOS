"""AI Control Plane Agent Loop Hardening MCP/API Surface (T-03295 scaffold).

Owns every ``aios_agent_loop_*`` service tool (spec: docs/tasks/evidence/T-03294-spec.md):
annotated per the MCP ``ToolAnnotations`` hints, with input-schema constraints taken from
the same constants the service enforces (LOOPMCP-INV1..LOOPMCP-INV4).
"""

from __future__ import annotations

from typing import Annotated, Any, Dict, Optional

from mcp.types import ToolAnnotations
from pydantic import Field

from aiosh_mcp.agent_loop_cli import MAX_HISTORY_LIMIT, MAX_TOKEN_CHARS
from aiosh_mcp.agent_loop_data_model import MAX_REGISTRY_CAPACITY
from aiosh_mcp.agent_loop_service import (
    MAX_ACTION_INTENT_CHARS,
    MAX_REASON_CHARS,
    MAX_TOKENS_PER_TURN,
    AgentLoopService,
)

LOOPMCP_ERR_AUDIT_READ = "LOOPMCP_ERR_AUDIT_READ"

# ---- schema types (LOOPMCP-INV3: one source of limits) ------------------------
LoopIdArg = Annotated[str, Field(pattern=r"^[a-zA-Z0-9_\-]{8,64}$", description="Loop id")]
TokenArg = Annotated[str, Field(min_length=1, max_length=MAX_TOKEN_CHARS,
                                description="PEP grant id (redeemed on start, loop-bound afterwards)")]
IntentArg = Annotated[str, Field(min_length=1, max_length=MAX_ACTION_INTENT_CHARS)]
ReasonArg = Annotated[str, Field(min_length=1, max_length=MAX_REASON_CHARS)]
ToolNameArg = Annotated[Optional[str], Field(default=None, pattern=r"^[A-Za-z0-9_.\-]{1,128}$")]
TokensArg = Annotated[int, Field(default=0, ge=0, le=MAX_TOKENS_PER_TURN)]
HistoryLimitArg = Annotated[int, Field(default=100, ge=1, le=MAX_HISTORY_LIMIT)]

# ---- annotations (LOOPMCP-INV2) -------------------------------------------------
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
MUTATING = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)
TERMINATING = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)
TERMINATING_IDEMPOTENT = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True,
                                         openWorldHint=False)

TOOL_ANNOTATIONS: Dict[str, ToolAnnotations] = {
    "aios_agent_loop_start": MUTATING,
    "aios_agent_loop_advance": MUTATING,
    "aios_agent_loop_abort": TERMINATING_IDEMPOTENT,
    "aios_agent_loop_complete": TERMINATING,
    "aios_agent_loop_snapshot": READ_ONLY,
    "aios_agent_loop_list": READ_ONLY,
    "aios_agent_loop_history": READ_ONLY,
}

MAX_LIST_LOOPS = MAX_REGISTRY_CAPACITY


def register_agent_loop_mcp_tools(
    mcp_app: Any,
    service: Optional[AgentLoopService] = None,
    db_path: Optional[str] = None,
) -> None:
    """Registers the seven agent-loop tools on ``mcp_app`` (T-03296)."""
    raise NotImplementedError("T-03296: register_agent_loop_mcp_tools")
