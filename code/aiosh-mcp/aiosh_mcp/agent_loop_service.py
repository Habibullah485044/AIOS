"""AI Control Plane Agent Loop Hardening Core Service (T-03275 scaffold).

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
        """Initializes a new loop in INIT state. Mutating: requires PoR capability token (LOOPSERV-INV5)."""
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
        raise NotImplementedError("start_loop scaffolded for T-03275")

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
                "Capability token required to advance agent loop turn",
                loop_id,
            )
        raise NotImplementedError("advance_turn scaffolded for T-03275")

    def abort_loop(self, loop_id: str, reason: str, capability_token: str = "") -> LoopSnapshot:
        """Transitions active loop directly to ABORTED state."""
        if not capability_token or not capability_token.strip():
            raise AgentLoopServiceError(
                LOOPSERV_ERR_UNAUTHORIZED,
                "Capability token required to abort agent loop",
                loop_id,
            )
        raise NotImplementedError("abort_loop scaffolded for T-03275")

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
