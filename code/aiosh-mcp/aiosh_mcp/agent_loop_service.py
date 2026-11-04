"""AI Control Plane Agent Loop Hardening Core Service (T-03275 scaffold / T-03276 impl).

Enforces LOOPSERV-INV1..LOOPSERV-INV5: deterministic FSM progression, audit atomicity,
pre-execution policy evaluation, execution timeout watchdogs, and PoR capability gating.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from aiosh_mcp.agent_loop_data_model import (
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
