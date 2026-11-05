"""AI Control Plane Agent Loop Hardening MCP/API Surface (T-03295 scaffold / T-03296 impl / T-03300 hardening / T-03308 config).

Owns every ``aios_agent_loop_*`` service tool (spec: docs/tasks/evidence/T-03294-spec.md):
annotated per the MCP ``ToolAnnotations`` hints, with input-schema constraints taken from
the same constants the service enforces (LOOPMCP-INV1..LOOPMCP-INV4).
"""

from __future__ import annotations

import json
from typing import Annotated, Any, Callable, Dict, List, Literal, Optional

import anyio
import anyio.to_thread

from mcp.types import ToolAnnotations
from pydantic import Field

from aiosh_mcp.agent_loop_cli import MAX_HISTORY_LIMIT, MAX_TOKEN_CHARS
from aiosh_mcp.agent_loop_config import audit_degraded, default_config, loop_config_for, process_config
from aiosh_mcp.agent_loop_config import resolve as resolve_config
from aiosh_mcp.agent_loop_data_model import MAX_REGISTRY_CAPACITY
from aiosh_mcp.agent_loop_data_model import LoopConfig, LoopResultEnvelope
from aiosh_mcp.agent_loop_gate import HistoryReadError, read_loop_history
from aiosh_mcp.agent_loop_observability import (
    DEFAULT_WINDOW,
    LOOPOBS_ERR_READ,
    MAX_WINDOW,
    ObservabilityReadError,
    health,
    ring_metrics,
)
from aiosh_mcp.agent_loop_service import (
    _GLOBAL_AGENT_LOOP_SERVICE,
    _error_envelope,
    MAX_ACTION_INTENT_CHARS,
    MAX_REASON_CHARS,
    MAX_TOKENS_PER_TURN,
    AgentLoopService,
)

LOOPMCP_ERR_AUDIT_READ = "LOOPMCP_ERR_AUDIT_READ"
LOOPMCP_ERR_TIMEOUT = "LOOPMCP_ERR_TIMEOUT"

#: Wall-clock bound per tool call (covers the 5 s SQLite busy wait with headroom).
TOOL_CALL_TIMEOUT_S = 15.0
#: Response budget for history pages (whole events are never split).
MAX_RESPONSE_BYTES = 1024 * 1024
DEFAULT_STEPS_TAIL = 100

# ---- schema types (LOOPMCP-INV3: one source of limits) ------------------------
LoopIdArg = Annotated[str, Field(pattern=r"^[a-zA-Z0-9_\-]{8,64}$", description="Loop id")]
# No min_length: an empty token must reach the service and come back as LOOPSERV_ERR_UNAUTHORIZED.
TokenArg = Annotated[str, Field(default="", max_length=MAX_TOKEN_CHARS,
                                description="PEP grant id (redeemed on start, loop-bound afterwards)")]
IntentArg = Annotated[str, Field(min_length=1, max_length=MAX_ACTION_INTENT_CHARS)]
ReasonArg = Annotated[str, Field(min_length=1, max_length=MAX_REASON_CHARS)]
ToolNameArg = Annotated[Optional[str], Field(default=None, pattern=r"^[a-z0-9_.\-]{1,128}$")]
TokensArg = Annotated[int, Field(default=0, ge=0, le=MAX_TOKENS_PER_TURN)]
HistoryLimitArg = Annotated[int, Field(default=100, ge=1, le=MAX_HISTORY_LIMIT)]
AfterIdArg = Annotated[int, Field(default=0, ge=0, description="Return events with id > after_id (pagination cursor)")]
StepsTailArg = Annotated[Optional[int], Field(default=None, ge=0, le=1000,
                                                description="Most recent steps to include (default: configured)")]

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
    "aios_agent_loop_config": READ_ONLY,
    "aios_agent_loop_metrics": READ_ONLY,
    "aios_agent_loop_doc": READ_ONLY,
    "aios_agent_loop_validate": READ_ONLY,
    "aios_agent_loop_recover": MUTATING,
}

MAX_LIST_LOOPS = MAX_REGISTRY_CAPACITY


def _ok(data: Dict[str, Any]) -> Dict[str, Any]:
    return LoopResultEnvelope(ok=True, data=data).to_dict()


async def _run(work: Callable[[], Dict[str, Any]], mutating: bool,
               timeout_s: float = TOOL_CALL_TIMEOUT_S, limiter: Any = None) -> Dict[str, Any]:
    """Runs blocking service/SQLite work off the event loop with a bounded wall-clock (T-03300).

    FastMCP calls sync tools on the event-loop thread, so a locked audit DB (busy_timeout 5 s)
    used to stall every other request on the stdio server.
    """
    try:
        with anyio.fail_after(timeout_s):
            return await anyio.to_thread.run_sync(work, abandon_on_cancel=True, limiter=limiter)
    except TimeoutError:
        hint = (" outcome unknown: check aios_agent_loop_snapshot / aios_agent_loop_history before retrying"
                if mutating else "")
        return LoopResultEnvelope(ok=False, error_code=LOOPMCP_ERR_TIMEOUT,
                                  error=f"{LOOPMCP_ERR_TIMEOUT}: tool call exceeded {timeout_s}s;{hint}"
                                  ).to_dict()
    except HistoryReadError as exc:
        return LoopResultEnvelope(ok=False, error=str(exc), error_code=LOOPMCP_ERR_AUDIT_READ).to_dict()
    except Exception as exc:
        return _error_envelope(exc)


def _snapshot_view(snap: Any, steps_tail: int) -> Dict[str, Any]:
    """Snapshot dict with only the last ``steps_tail`` steps (bounded response)."""
    d = snap.to_dict()
    total = len(d["steps"])
    d["steps"] = d["steps"][total - steps_tail:] if steps_tail else []
    return {"snapshot": d, "steps_total": total}


def _page_events(events: List[Dict[str, Any]], budget: int = MAX_RESPONSE_BYTES) -> Dict[str, Any]:
    """Keeps whole events until MAX_RESPONSE_BYTES; reports a cursor if more remain."""
    kept: List[Dict[str, Any]] = []
    size = 0
    for ev in events:
        size += len(json.dumps(ev, default=str))
        if kept and size > budget:
            return {"events": kept, "truncated": True, "next_after_id": kept[-1]["id"]}
        kept.append(ev)
    return {"events": kept, "truncated": False, "next_after_id": None}


def register_agent_loop_mcp_tools(
    mcp_app: Any,
    service: Optional[AgentLoopService] = None,
    db_path: Optional[str] = None,
    settings: Optional[Dict[str, Any]] = None,
) -> None:
    """Registers the eight agent-loop tools on ``mcp_app`` (T-03296; async + bounded since T-03300).

    ``service`` and ``db_path`` default to the process-wide service and ``$AIOSH_HOME/audit.db``;
    they are resolved per call so tests and operators can swap the gate at runtime.
    ``settings`` (T-03308) is an already-resolved config dict; by default it comes from
    ``agent_loop_config.resolve()`` once, at registration.
    """
    # ``settings`` is a programmatic/test hook: taken as given (no clamping) and labelled "settings".
    resolved = process_config() if settings is None else {
        "config": {**default_config(), **settings},
        "source": {**{k: "default" for k in default_config()}, **{k: "settings" for k in settings}},
        "rejected": {}, "errors": []}
    cfg = resolved["config"]
    if settings is None and resolved["errors"] and not resolved.get("_audited"):
        # Fail-open to defaults must leave an honest audit row (ADR-0035 §F-2, T-03310).
        failure = audit_degraded(resolved, db_path)
        resolved["_audited"] = True
        if failure:
            resolved["errors"].append(failure)
    timeout_s = float(cfg["mcp_call_timeout_s"])
    page_bytes = int(cfg["history_page_bytes"])
    default_tail = int(cfg["snapshot_steps_tail"])

    metrics_limiter = anyio.CapacityLimiter(1)

    async def run(work: Callable[[], Dict[str, Any]], mutating: bool) -> Dict[str, Any]:
        return await _run(work, mutating, timeout_s)

    def svc() -> AgentLoopService:
        return service if service is not None else _GLOBAL_AGENT_LOOP_SERVICE

    @mcp_app.tool(name="aios_agent_loop_start", annotations=TOOL_ANNOTATIONS["aios_agent_loop_start"])
    async def aios_agent_loop_start(
        loop_id: LoopIdArg,
        capability_token: TokenArg = "",
        max_iterations: Annotated[Optional[int], Field(ge=1, le=100)] = None,
        max_total_tokens: Annotated[Optional[int], Field(ge=100, le=1_000_000)] = None,
        timeout_ms_per_step: Annotated[Optional[float], Field(ge=1000.0, le=120000.0)] = None,
        total_timeout_ms: Annotated[Optional[float], Field(ge=5000.0, le=1_800_000.0)] = None,
        consecutive_failure_limit: Annotated[Optional[int], Field(ge=1, le=10)] = None,
    ) -> dict:
        """Starts a hardened agent loop (INIT -> OBSERVE). Mutating: redeems the capability token as a PEP grant.
        Omitted budgets use the configured defaults (aios_agent_loop_config)."""
        def work() -> Dict[str, Any]:
            loop_cfg = loop_config_for(loop_id, resolved, max_iterations=max_iterations,
                                       max_total_tokens=max_total_tokens, timeout_ms_per_step=timeout_ms_per_step,
                                       total_timeout_ms=total_timeout_ms,
                                       consecutive_failure_limit=consecutive_failure_limit)
            s = svc()
            snap = s.start_loop(loop_cfg, capability_token=capability_token)
            return _ok({"snapshot": snap.to_dict(), "run_id": s.run_id(loop_id)})
        return await run(work, mutating=True)

    @mcp_app.tool(name="aios_agent_loop_advance", annotations=TOOL_ANNOTATIONS["aios_agent_loop_advance"])
    async def aios_agent_loop_advance(
        loop_id: LoopIdArg,
        action_intent: IntentArg,
        capability_token: TokenArg = "",
        tool_name: ToolNameArg = None,
        tool_args: Optional[Dict[str, Any]] = None,
        tokens_consumed: TokensArg = 0,
        policy_allowed: bool = True,
    ) -> dict:
        """Advances one turn through the policy gate (refused steps return ok=true with outcome=refused)."""
        def work() -> Dict[str, Any]:
            s = svc()
            step = s.advance_turn(loop_id=loop_id, action_intent=action_intent, tool_name=tool_name,
                                  tool_args=tool_args, tokens_consumed=tokens_consumed,
                                  policy_allowed=policy_allowed, capability_token=capability_token)
            snap = s.get_snapshot(loop_id)
            return _ok({"step": step.to_dict(), "state": snap.current_state.value,
                        "is_terminated": snap.is_terminated})
        return await run(work, mutating=True)

    @mcp_app.tool(name="aios_agent_loop_abort", annotations=TOOL_ANNOTATIONS["aios_agent_loop_abort"])
    async def aios_agent_loop_abort(loop_id: LoopIdArg, reason: ReasonArg, capability_token: TokenArg = "") -> dict:
        """Aborts an active loop (idempotent on an already-terminated loop). Mutating: loop-bound token."""
        return await run(lambda: _ok({"snapshot": svc().abort_loop(
            loop_id, reason, capability_token=capability_token).to_dict()}), mutating=True)

    @mcp_app.tool(name="aios_agent_loop_complete", annotations=TOOL_ANNOTATIONS["aios_agent_loop_complete"])
    async def aios_agent_loop_complete(loop_id: LoopIdArg, capability_token: TokenArg = "") -> dict:
        """Ends an active loop normally (OBSERVE -> COMPLETED). Mutating: loop-bound token."""
        return await run(lambda: _ok({"snapshot": svc().complete_loop(
            loop_id, capability_token=capability_token).to_dict()}), mutating=True)

    @mcp_app.tool(name="aios_agent_loop_snapshot", annotations=TOOL_ANNOTATIONS["aios_agent_loop_snapshot"])
    async def aios_agent_loop_snapshot(loop_id: LoopIdArg, steps_tail: StepsTailArg = None) -> dict:
        """Returns the loop snapshot with its last ``steps_tail`` steps and ``steps_total``. Read-only, no token."""
        tail = default_tail if steps_tail is None else steps_tail
        return await run(lambda: _ok(_snapshot_view(svc().get_snapshot(loop_id), tail)), mutating=False)

    @mcp_app.tool(name="aios_agent_loop_list", annotations=TOOL_ANNOTATIONS["aios_agent_loop_list"])
    async def aios_agent_loop_list(include_terminated: bool = False) -> dict:
        """Lists loops held by this server (active only by default). Read-only, no token."""
        def work() -> Dict[str, Any]:
            s = svc()
            with s._lock:
                snaps = list(s._loops.values())
            loops = [{"loop_id": x.loop_id, "current_state": x.current_state.value,
                      "current_iteration": x.current_iteration, "total_tokens_used": x.total_tokens_used,
                      "is_terminated": x.is_terminated}
                     for x in snaps if include_terminated or not x.is_terminated][:MAX_LIST_LOOPS]
            return _ok({"loops": loops})
        return await run(work, mutating=False)

    @mcp_app.tool(name="aios_agent_loop_history", annotations=TOOL_ANNOTATIONS["aios_agent_loop_history"])
    async def aios_agent_loop_history(loop_id: LoopIdArg, limit: HistoryLimitArg = 100,
                                      after_id: AfterIdArg = 0) -> dict:
        """Returns this loop's aios.agent_loop.* audit rows after ``after_id``, oldest first, at most ~1 MiB per
        page (``truncated`` / ``next_after_id`` for the next page). Read-only (DB opened mode=ro), no token."""
        return await run(lambda: _ok({"loop_id": loop_id, **_page_events(
            read_loop_history(db_path, loop_id, limit, after_id=after_id), page_bytes)}), mutating=False)

    @mcp_app.tool(name="aios_agent_loop_config", annotations=TOOL_ANNOTATIONS["aios_agent_loop_config"])
    async def aios_agent_loop_config() -> dict:
        """Returns the agent-loop configuration this server resolved at startup: values, where each came from
        (argument/env/file/default/env_invalid/config_invalid) and any rejected input. Read-only, no token."""
        return _ok({"config": cfg, "source": resolved["source"], "rejected": resolved.get("rejected", {}),
                    "degraded": bool(resolved["errors"]),
                    "errors": resolved["errors"]})

    @mcp_app.tool(name="aios_agent_loop_metrics", annotations=TOOL_ANNOTATIONS["aios_agent_loop_metrics"])
    async def aios_agent_loop_metrics(
        window: Annotated[int, Field(ge=1, le=MAX_WINDOW)] = DEFAULT_WINDOW,
    ) -> dict:
        """Agent-loop telemetry (T-03338): ring-derived metrics over the newest ``window`` agent-loop audit rows,
        live gauges/counters of this server, and health (ok/degraded/failing). Read-only, no token;
        grant ids are never emitted (hashed)."""
        def work() -> Dict[str, Any]:
            live = svc().stats()
            try:
                ring = ring_metrics(db_path, window)
                # Health always looks at the default window, so a caller cannot hide signals with a tiny one.
                basis = ring if window >= DEFAULT_WINDOW else ring_metrics(db_path, DEFAULT_WINDOW)
                from aiosh_mcp.agent_loop_recovery import RecoveryError, validate_ring
                try:   # orphaned runs (T-03358) degrade health until recovered
                    ring["orphaned_runs"] = basis["orphaned_runs"] = len(
                        validate_ring(db_path, 900, svc().live_run_ids())["orphaned"])
                except RecoveryError:
                    ring["orphaned_runs"] = basis["orphaned_runs"] = None
            except ObservabilityReadError as exc:
                ring = basis = {"error": str(exc)}
            return _ok({"ring": ring, "live": live,
                        "health": health(basis, live, config_degraded=bool(resolved["errors"]))})
        # One metrics scan at a time, on its own limiter: tokenless calls cannot exhaust the shared pool.
        return await _run(work, False, timeout_s, metrics_limiter)

    @mcp_app.tool(name="aios_agent_loop_validate", annotations=TOOL_ANNOTATIONS["aios_agent_loop_validate"])
    async def aios_agent_loop_validate(grace_s: Annotated[float, Field(ge=0, le=86400 * 30)] = 900,
                                       verify_chain: bool = False) -> dict:
        """Validates every loop run in the audit ring (T-03358): orphaned runs (no terminal row, older than
        grace_s, not live here), structural problems, and chain verification. Read-only, no token."""
        from aiosh_mcp.agent_loop_recovery import RecoveryError, validate_ring

        def work() -> Dict[str, Any]:
            try:
                return _ok(validate_ring(db_path, grace_s, svc().live_run_ids(), verify_chain=verify_chain))
            except RecoveryError as exc:
                return LoopResultEnvelope(ok=False, error=str(exc), error_code=exc.code).to_dict()
        return await _run(work, False, timeout_s, metrics_limiter)

    @mcp_app.tool(name="aios_agent_loop_recover", annotations=TOOL_ANNOTATIONS["aios_agent_loop_recover"])
    async def aios_agent_loop_recover(capability_token: TokenArg = "",
                                      grace_s: Annotated[float, Field(ge=0, le=86400 * 30)] = 900) -> dict:
        """Closes orphaned runs honestly (T-03358): one aios.agent_loop.recovered row per run whose process
        ended without a terminal row. Mutating: redeems a grant scoped to aios.agent_loop.recover. Never
        touches runs this server still holds; idempotent."""
        from aiosh_mcp.agent_loop_recovery import RecoveryError, recover_orphans

        def work() -> Dict[str, Any]:
            try:
                return _ok(recover_orphans(db_path, capability_token, grace_s, svc().live_run_ids()))
            except RecoveryError as exc:
                return LoopResultEnvelope(ok=False, error=str(exc), error_code=exc.code,
                                          data={"recovered": exc.recovered}).to_dict()
        return await run(work, mutating=True)

    @mcp_app.tool(name="aios_agent_loop_doc", annotations=TOOL_ANNOTATIONS["aios_agent_loop_doc"])
    async def aios_agent_loop_doc(
        section: Optional[Literal["tools", "errors", "config", "cli", "policy"]] = None,
    ) -> dict:
        """Reference for the agent-loop subsystem generated from code at call time (T-03348): tools with
        schemas/annotations, every error code with its meaning, config fields/bounds/env names, CLI
        subcommands, the step-policy order. Read-only, no token; never contains secrets or env values."""
        from aiosh_mcp.agent_loop_doc import reference
        return await run(lambda: _ok(reference(section)), mutating=False)
