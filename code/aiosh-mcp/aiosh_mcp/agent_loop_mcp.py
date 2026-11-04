"""AI Control Plane Agent Loop Hardening MCP/API Surface (T-03295 scaffold / T-03296 impl).

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
from aiosh_mcp.agent_loop_data_model import LoopConfig, LoopResultEnvelope
from aiosh_mcp.agent_loop_gate import HistoryReadError, read_loop_history
from aiosh_mcp.agent_loop_service import (
    _GLOBAL_AGENT_LOOP_SERVICE,
    _error_envelope,
    MAX_ACTION_INTENT_CHARS,
    MAX_REASON_CHARS,
    MAX_TOKENS_PER_TURN,
    AgentLoopService,
)

LOOPMCP_ERR_AUDIT_READ = "LOOPMCP_ERR_AUDIT_READ"

# ---- schema types (LOOPMCP-INV3: one source of limits) ------------------------
LoopIdArg = Annotated[str, Field(pattern=r"^[a-zA-Z0-9_\-]{8,64}$", description="Loop id")]
# No min_length: an empty token must reach the service and come back as LOOPSERV_ERR_UNAUTHORIZED.
TokenArg = Annotated[str, Field(default="", max_length=MAX_TOKEN_CHARS,
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


def _ok(data: Dict[str, Any]) -> Dict[str, Any]:
    return LoopResultEnvelope(ok=True, data=data).to_dict()


def register_agent_loop_mcp_tools(
    mcp_app: Any,
    service: Optional[AgentLoopService] = None,
    db_path: Optional[str] = None,
) -> None:
    """Registers the seven agent-loop tools on ``mcp_app`` (T-03296).

    ``service`` and ``db_path`` default to the process-wide service and ``$AIOSH_HOME/audit.db``;
    they are resolved per call so tests and operators can swap the gate at runtime.
    """

    def svc() -> AgentLoopService:
        return service if service is not None else _GLOBAL_AGENT_LOOP_SERVICE

    @mcp_app.tool(name="aios_agent_loop_start", annotations=TOOL_ANNOTATIONS["aios_agent_loop_start"])
    def aios_agent_loop_start(
        loop_id: LoopIdArg,
        capability_token: TokenArg = "",
        max_iterations: Annotated[int, Field(ge=1, le=100)] = 25,
        max_total_tokens: Annotated[int, Field(ge=100, le=1_000_000)] = 32768,
        timeout_ms_per_step: Annotated[float, Field(ge=1000.0, le=120000.0)] = 30000.0,
        total_timeout_ms: Annotated[float, Field(ge=5000.0, le=1_800_000.0)] = 300000.0,
        consecutive_failure_limit: Annotated[int, Field(ge=1, le=10)] = 3,
    ) -> dict:
        """Starts a hardened agent loop (INIT -> OBSERVE). Mutating: redeems the capability token as a PEP grant."""
        try:
            cfg = LoopConfig(loop_id=loop_id, max_iterations=max_iterations, max_total_tokens=max_total_tokens,
                             timeout_ms_per_step=timeout_ms_per_step, total_timeout_ms=total_timeout_ms,
                             consecutive_failure_limit=consecutive_failure_limit)
            return _ok({"snapshot": svc().start_loop(cfg, capability_token=capability_token).to_dict()})
        except Exception as exc:
            return _error_envelope(exc)

    @mcp_app.tool(name="aios_agent_loop_advance", annotations=TOOL_ANNOTATIONS["aios_agent_loop_advance"])
    def aios_agent_loop_advance(
        loop_id: LoopIdArg,
        action_intent: IntentArg,
        capability_token: TokenArg = "",
        tool_name: ToolNameArg = None,
        tool_args: Optional[Dict[str, Any]] = None,
        tokens_consumed: TokensArg = 0,
        policy_allowed: bool = True,
    ) -> dict:
        """Advances one turn through the policy gate (refused steps return ok=true with outcome=refused)."""
        try:
            s = svc()
            step = s.advance_turn(loop_id=loop_id, action_intent=action_intent, tool_name=tool_name,
                                  tool_args=tool_args, tokens_consumed=tokens_consumed,
                                  policy_allowed=policy_allowed, capability_token=capability_token)
            snap = s.get_snapshot(loop_id)
            return _ok({"step": step.to_dict(), "state": snap.current_state.value,
                        "is_terminated": snap.is_terminated})
        except Exception as exc:
            return _error_envelope(exc)

    @mcp_app.tool(name="aios_agent_loop_abort", annotations=TOOL_ANNOTATIONS["aios_agent_loop_abort"])
    def aios_agent_loop_abort(loop_id: LoopIdArg, reason: ReasonArg, capability_token: TokenArg = "") -> dict:
        """Aborts an active loop (idempotent on an already-terminated loop). Mutating: loop-bound token."""
        try:
            return _ok({"snapshot": svc().abort_loop(loop_id, reason, capability_token=capability_token).to_dict()})
        except Exception as exc:
            return _error_envelope(exc)

    @mcp_app.tool(name="aios_agent_loop_complete", annotations=TOOL_ANNOTATIONS["aios_agent_loop_complete"])
    def aios_agent_loop_complete(loop_id: LoopIdArg, capability_token: TokenArg = "") -> dict:
        """Ends an active loop normally (OBSERVE -> COMPLETED). Mutating: loop-bound token."""
        try:
            return _ok({"snapshot": svc().complete_loop(loop_id, capability_token=capability_token).to_dict()})
        except Exception as exc:
            return _error_envelope(exc)

    @mcp_app.tool(name="aios_agent_loop_snapshot", annotations=TOOL_ANNOTATIONS["aios_agent_loop_snapshot"])
    def aios_agent_loop_snapshot(loop_id: LoopIdArg) -> dict:
        """Returns the service-held loop snapshot. Read-only, no token."""
        try:
            return _ok({"snapshot": svc().get_snapshot(loop_id).to_dict()})
        except Exception as exc:
            return _error_envelope(exc)

    @mcp_app.tool(name="aios_agent_loop_list", annotations=TOOL_ANNOTATIONS["aios_agent_loop_list"])
    def aios_agent_loop_list(include_terminated: bool = False) -> dict:
        """Lists loops held by this server (active only by default). Read-only, no token."""
        try:
            s = svc()
            with s._lock:
                snaps = list(s._loops.values())
            loops = [{"loop_id": x.loop_id, "current_state": x.current_state.value,
                      "current_iteration": x.current_iteration, "total_tokens_used": x.total_tokens_used,
                      "is_terminated": x.is_terminated}
                     for x in snaps if include_terminated or not x.is_terminated][:MAX_LIST_LOOPS]
            return _ok({"loops": loops})
        except Exception as exc:
            return _error_envelope(exc)

    @mcp_app.tool(name="aios_agent_loop_history", annotations=TOOL_ANNOTATIONS["aios_agent_loop_history"])
    def aios_agent_loop_history(loop_id: LoopIdArg, limit: HistoryLimitArg = 100) -> dict:
        """Returns this loop's aios.agent_loop.* audit rows, oldest first. Read-only (DB opened mode=ro), no token."""
        try:
            return _ok({"loop_id": loop_id, "events": read_loop_history(db_path, loop_id, limit)})
        except HistoryReadError as exc:
            return LoopResultEnvelope(ok=False, error=str(exc), error_code=LOOPMCP_ERR_AUDIT_READ).to_dict()
        except Exception as exc:
            return _error_envelope(exc)
