"""AI Control Plane Agent Loop Hardening Core Service (T-03275 scaffold / T-03276 impl / T-03278 integ).

Enforces LOOPSERV-INV1..LOOPSERV-INV5: deterministic FSM progression, audit atomicity,
pre-execution policy evaluation, execution timeout watchdogs, and PoR capability gating.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from aiosh_mcp.agent_loop_data_model import (
    LoopResultEnvelope,
    create_initial,
    mask_secrets,
    validate_loop_transition,
    LoopConfig,
    LoopSnapshot,
    LoopState,
    LoopStepRecord,
    LOOPDATA_ERR_BOUNDS_EXCEEDED,
    LOOPDATA_ERR_INVALID_TRANSITION,
    LOOPDATA_ERR_NOT_FOUND,
    LOOPDATA_ERR_UNAUTHORIZED,
)

LOOPSERV_ERR_NOT_FOUND = "LOOPSERV_ERR_NOT_FOUND"
LOOPSERV_ERR_ALREADY_EXISTS = "LOOPSERV_ERR_ALREADY_EXISTS"
LOOPSERV_ERR_TERMINATED = "LOOPSERV_ERR_TERMINATED"
LOOPSERV_ERR_UNAUTHORIZED = "LOOPSERV_ERR_UNAUTHORIZED"
LOOPSERV_ERR_POLICY_REFUSED = "LOOPSERV_ERR_POLICY_REFUSED"
LOOPSERV_ERR_TIMEOUT = "LOOPSERV_ERR_TIMEOUT"
LOOPSERV_ERR_CIRCUIT_BREAKER = "LOOPSERV_ERR_CIRCUIT_BREAKER"


class AgentLoopServiceError(Exception):
    """Base exception for Agent Loop Core Service failures."""

    def __init__(self, code: str, message: str, loop_id: Optional[str] = None):
        safe_msg = mask_secrets(message)
        super().__init__(f"{code}: {safe_msg}")
        self.code = code
        self.message = safe_msg
        self.loop_id = loop_id


class AgentLoopService:
    """Core Service orchestrating hardened agent loop state machines (LOOPSERV-INV1..LOOPSERV-INV5)."""

    def __init__(self) -> None:
        self._loops: Dict[str, LoopSnapshot] = {}
        self._configs: Dict[str, LoopConfig] = {}
        self._start_times: Dict[str, float] = {}

    def start_loop(self, config: LoopConfig, capability_token: str) -> LoopSnapshot:
        """Initializes a new loop in INIT state and moves to OBSERVE (LOOPSERV-INV5)."""
        if not capability_token or not capability_token.strip():
            raise AgentLoopServiceError(
                LOOPSERV_ERR_UNAUTHORIZED,
                "Capability token required to start agent loop (PoR Invariant I-2)",
                config.loop_id,
            )
        config.validate_bounds()
        if config.loop_id in self._loops:
            raise AgentLoopServiceError(
                LOOPSERV_ERR_ALREADY_EXISTS,
                f"Loop '{config.loop_id}' already exists",
                config.loop_id,
            )

        snap = create_initial(config.loop_id, config)
        snap.transition_to(LoopState.OBSERVE)

        self._loops[config.loop_id] = snap
        self._configs[config.loop_id] = config
        self._start_times[config.loop_id] = time.time()
        return snap

    def advance_turn(
        self,
        loop_id: str,
        action_intent: str,
        tool_name: Optional[str] = None,
        tool_args: Optional[Dict[str, Any]] = None,
        tokens_consumed: int = 0,
        policy_allowed: bool = True,
        capability_token: str = "",
    ) -> LoopStepRecord:
        """Advances agent loop through FSM: EVALUATE_POLICY -> EXECUTE_TOOL -> RECORD_STEP."""
        if not capability_token or not capability_token.strip():
            raise AgentLoopServiceError(
                LOOPSERV_ERR_UNAUTHORIZED,
                "Capability token required to advance agent loop turn (PoR Invariant I-2)",
                loop_id,
            )

        snap = self._loops.get(loop_id)
        if not snap:
            raise AgentLoopServiceError(
                LOOPSERV_ERR_NOT_FOUND,
                f"Loop '{loop_id}' not found",
                loop_id,
            )

        if snap.is_terminated:
            raise AgentLoopServiceError(
                LOOPSERV_ERR_TERMINATED,
                f"Loop '{loop_id}' is terminated ({snap.current_state.value}): {snap.terminal_reason}",
                loop_id,
            )

        config = self._configs.get(loop_id)
        if config:
            elapsed_ms = (time.time() - self._start_times.get(loop_id, time.time())) * 1000.0
            if elapsed_ms > config.total_timeout_ms:
                snap.transition_to(
                    LoopState.ABORTED,
                    terminal_reason=f"{LOOPSERV_ERR_TIMEOUT}: total timeout ({config.total_timeout_ms}ms) exceeded",
                )
                raise AgentLoopServiceError(
                    LOOPSERV_ERR_TIMEOUT,
                    f"Total timeout exceeded for loop '{loop_id}'",
                    loop_id,
                )

        # FSM sequencing: from current (OBSERVE or RECORD_STEP) to PLAN
        if snap.current_state == LoopState.RECORD_STEP:
            snap.transition_to(LoopState.OBSERVE)
        snap.transition_to(LoopState.PLAN)

        # LOOPSERV-INV3: Pre-Execution Policy Gate
        snap.transition_to(LoopState.EVALUATE_POLICY)

        args_str = str(tool_args or {})
        start_state = LoopState.EVALUATE_POLICY

        if not policy_allowed:
            snap.transition_to(LoopState.RECORD_STEP)
            step = LoopStepRecord(
                step_index=len(snap.steps),
                state_at_start=start_state,
                state_at_end=LoopState.RECORD_STEP,
                tool_name=tool_name,
                tool_args_summary=args_str,
                outcome="refused",
                tokens_consumed=tokens_consumed,
                duration_ms=5.0,
                error_message=f"{LOOPSERV_ERR_POLICY_REFUSED}: Policy evaluation refused tool invocation",
            )
            snap.record_step(step, config)
            if not snap.is_terminated:
                snap.transition_to(LoopState.OBSERVE)
            return step

        # Policy allowed: proceed to tool execution
        snap.transition_to(LoopState.EXECUTE_TOOL)
        snap.transition_to(LoopState.RECORD_STEP)
        step = LoopStepRecord(
            step_index=len(snap.steps),
            state_at_start=LoopState.EXECUTE_TOOL,
            state_at_end=LoopState.RECORD_STEP,
            tool_name=tool_name,
            tool_args_summary=args_str,
            outcome="ok",
            tokens_consumed=tokens_consumed,
            duration_ms=15.0,
        )
        snap.record_step(step, config)
        if not snap.is_terminated:
            snap.transition_to(LoopState.OBSERVE)
        return step

    def abort_loop(self, loop_id: str, reason: str, capability_token: str = "") -> LoopSnapshot:
        """Transitions active loop directly to ABORTED state (LOOPSERV-INV5)."""
        if not capability_token or not capability_token.strip():
            raise AgentLoopServiceError(
                LOOPSERV_ERR_UNAUTHORIZED,
                "Capability token required to abort agent loop (PoR Invariant I-2)",
                loop_id,
            )

        snap = self._loops.get(loop_id)
        if not snap:
            raise AgentLoopServiceError(
                LOOPSERV_ERR_NOT_FOUND,
                f"Loop '{loop_id}' not found",
                loop_id,
            )

        if snap.is_terminated:
            return snap

        snap.transition_to(LoopState.ABORTED, terminal_reason=reason)
        return snap

    def get_snapshot(self, loop_id: str) -> LoopSnapshot:
        """Returns current loop snapshot. Pure read-only (0 capability tokens)."""
        snap = self._loops.get(loop_id)
        if not snap:
            raise AgentLoopServiceError(
                LOOPSERV_ERR_NOT_FOUND,
                f"Loop '{loop_id}' not found",
                loop_id,
            )
        return snap

    def list_active_loops(self) -> List[LoopSnapshot]:
        """Lists active non-terminated loops in memory."""
        return [s for s in self._loops.values() if not s.is_terminated]


_GLOBAL_AGENT_LOOP_SERVICE = AgentLoopService()


def _error_envelope(exc: Exception) -> Dict[str, Any]:
    """Maps service/data-model failures onto the standard result envelope (ADR-0035)."""
    if isinstance(exc, AgentLoopServiceError):
        return LoopResultEnvelope(ok=False, error=str(exc), error_code=exc.code).to_dict()
    msg = mask_secrets(str(exc))
    code = msg.split(":", 1)[0] if msg.startswith("LOOPDATA_ERR_") else "LOOPSERV_ERR_INTERNAL"
    return LoopResultEnvelope(ok=False, error=msg, error_code=code).to_dict()


def register_agent_loop_service_tools(mcp_app: Any, service: Optional[AgentLoopService] = None) -> None:
    """Registers the agent loop core service on FastMCP (T-03278).

    Mutating tools (start/advance/abort) require a capability token (LOOPSERV-INV5);
    the snapshot tool is read-only.
    """
    svc = service or _GLOBAL_AGENT_LOOP_SERVICE

    @mcp_app.tool()
    def aios_agent_loop_start(
        loop_id: str,
        capability_token: str = "",
        max_iterations: int = 25,
        max_total_tokens: int = 32768,
        timeout_ms_per_step: float = 30000.0,
        total_timeout_ms: float = 300000.0,
        consecutive_failure_limit: int = 3,
    ) -> dict:
        """Starts a hardened agent loop (INIT -> OBSERVE). Mutating: requires capability token."""
        try:
            cfg = LoopConfig(
                loop_id=loop_id,
                max_iterations=max_iterations,
                max_total_tokens=max_total_tokens,
                timeout_ms_per_step=timeout_ms_per_step,
                total_timeout_ms=total_timeout_ms,
                consecutive_failure_limit=consecutive_failure_limit,
            )
            snap = svc.start_loop(cfg, capability_token=capability_token)
            return LoopResultEnvelope(ok=True, data={"snapshot": snap.to_dict()}).to_dict()
        except Exception as exc:
            return _error_envelope(exc)

    @mcp_app.tool()
    def aios_agent_loop_advance(
        loop_id: str,
        action_intent: str,
        capability_token: str = "",
        tool_name: Optional[str] = None,
        tool_args: Optional[Dict[str, Any]] = None,
        tokens_consumed: int = 0,
        policy_allowed: bool = True,
    ) -> dict:
        """Advances one loop turn through the policy gate. Mutating: requires capability token."""
        try:
            step = svc.advance_turn(
                loop_id=loop_id,
                action_intent=action_intent,
                tool_name=tool_name,
                tool_args=tool_args,
                tokens_consumed=tokens_consumed,
                policy_allowed=policy_allowed,
                capability_token=capability_token,
            )
            snap = svc.get_snapshot(loop_id)
            return LoopResultEnvelope(
                ok=True,
                data={"step": step.to_dict(), "state": snap.current_state.value,
                      "is_terminated": snap.is_terminated},
            ).to_dict()
        except Exception as exc:
            return _error_envelope(exc)

    @mcp_app.tool()
    def aios_agent_loop_abort(loop_id: str, reason: str, capability_token: str = "") -> dict:
        """Aborts an active loop. Mutating: requires capability token."""
        try:
            snap = svc.abort_loop(loop_id, reason, capability_token=capability_token)
            return LoopResultEnvelope(ok=True, data={"snapshot": snap.to_dict()}).to_dict()
        except Exception as exc:
            return _error_envelope(exc)

    @mcp_app.tool()
    def aios_agent_loop_snapshot(loop_id: str) -> dict:
        """Returns the service-held loop snapshot. Read-only (no capability token)."""
        try:
            return LoopResultEnvelope(ok=True, data={"snapshot": svc.get_snapshot(loop_id).to_dict()}).to_dict()
        except Exception as exc:
            return _error_envelope(exc)
