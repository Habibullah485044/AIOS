"""AI Control Plane Agent Loop Hardening Data Model (T-03265 scaffold).

Enforces LOOPDATA-INV1..LOOPDATA-INV5: monotonic step indexing, token conservation,
circuit breaker bounds, substrate serialization parity, and FSM transition determinism.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set

LOOPDATA_ERR_INVALID_STATE = "LOOPDATA_ERR_INVALID_STATE"
LOOPDATA_ERR_INVALID_TRANSITION = "LOOPDATA_ERR_INVALID_TRANSITION"
LOOPDATA_ERR_BOUNDS_EXCEEDED = "LOOPDATA_ERR_BOUNDS_EXCEEDED"
LOOPDATA_ERR_INVARIANT_VIOLATION = "LOOPDATA_ERR_INVARIANT_VIOLATION"

LOOP_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{8,64}$")
SECRET_PATTERN = re.compile(r"(sk-[a-zA-Z0-9_\-]{20,}|ghp_[a-zA-Z0-9_\-]{20,}|Bearer\s+[a-zA-Z0-9_\-\.]{20,})", re.IGNORECASE)


def mask_secrets(text: str) -> str:
    """Masks API keys, tokens, and authorization credentials."""
    if not text:
        return ""
    return SECRET_PATTERN.sub("[REDACTED_SECRET]", text)


class LoopState(str, Enum):
    INIT = "INIT"
    OBSERVE = "OBSERVE"
    PLAN = "PLAN"
    EVALUATE_POLICY = "EVALUATE_POLICY"
    EXECUTE_TOOL = "EXECUTE_TOOL"
    RECORD_STEP = "RECORD_STEP"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ABORTED = "ABORTED"


VALID_TRANSITIONS: Dict[LoopState, Set[LoopState]] = {
    LoopState.INIT: {LoopState.OBSERVE, LoopState.ABORTED},
    LoopState.OBSERVE: {LoopState.PLAN, LoopState.COMPLETED, LoopState.ABORTED},
    LoopState.PLAN: {LoopState.EVALUATE_POLICY, LoopState.COMPLETED, LoopState.FAILED, LoopState.ABORTED},
    LoopState.EVALUATE_POLICY: {LoopState.EXECUTE_TOOL, LoopState.RECORD_STEP, LoopState.FAILED, LoopState.ABORTED},
    LoopState.EXECUTE_TOOL: {LoopState.RECORD_STEP, LoopState.FAILED, LoopState.ABORTED},
    LoopState.RECORD_STEP: {LoopState.OBSERVE, LoopState.COMPLETED, LoopState.FAILED, LoopState.ABORTED},
    LoopState.COMPLETED: set(),
    LoopState.FAILED: set(),
    LoopState.ABORTED: set(),
}


def validate_loop_transition(from_state: LoopState, to_state: LoopState) -> None:
    """Validates deterministic FSM state transition (LOOPDATA-INV5)."""
    if from_state == to_state:
        return
    allowed = VALID_TRANSITIONS.get(from_state, set())
    if to_state not in allowed:
        raise ValueError(
            f"{LOOPDATA_ERR_INVALID_TRANSITION}: transition from {from_state.value} to {to_state.value} is forbidden"
        )


@dataclass(frozen=True)
class LoopConfig:
    loop_id: str
    max_iterations: int = 25
    max_total_tokens: int = 32768
    timeout_ms_per_step: float = 30000.0
    total_timeout_ms: float = 300000.0
    consecutive_failure_limit: int = 3

    def validate_bounds(self) -> None:
        """Enforces parameter bounds and loop_id syntax."""
        if not self.loop_id or not LOOP_ID_PATTERN.match(self.loop_id.strip()):
            raise ValueError(f"{LOOPDATA_ERR_BOUNDS_EXCEEDED}: invalid loop_id syntax: {self.loop_id}")
        if not (1 <= self.max_iterations <= 100):
            raise ValueError(f"{LOOPDATA_ERR_BOUNDS_EXCEEDED}: max_iterations must be in [1, 100]")
        if not (100 <= self.max_total_tokens <= 1000000):
            raise ValueError(f"{LOOPDATA_ERR_BOUNDS_EXCEEDED}: max_total_tokens must be in [100, 1000000]")
        if not (1000.0 <= self.timeout_ms_per_step <= 120000.0):
            raise ValueError(f"{LOOPDATA_ERR_BOUNDS_EXCEEDED}: timeout_ms_per_step must be in [1000.0, 120000.0]")
        if not (5000.0 <= self.total_timeout_ms <= 1800000.0):
            raise ValueError(f"{LOOPDATA_ERR_BOUNDS_EXCEEDED}: total_timeout_ms must be in [5000.0, 1800000.0]")
        if not (1 <= self.consecutive_failure_limit <= 10):
            raise ValueError(f"{LOOPDATA_ERR_BOUNDS_EXCEEDED}: consecutive_failure_limit must be in [1, 10]")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "loop_id": self.loop_id,
            "max_iterations": self.max_iterations,
            "max_total_tokens": self.max_total_tokens,
            "timeout_ms_per_step": self.timeout_ms_per_step,
            "total_timeout_ms": self.total_timeout_ms,
            "consecutive_failure_limit": self.consecutive_failure_limit,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LoopConfig":
        cfg = cls(
            loop_id=str(data.get("loop_id", "")),
            max_iterations=int(data.get("max_iterations", 25)),
            max_total_tokens=int(data.get("max_total_tokens", 32768)),
            timeout_ms_per_step=float(data.get("timeout_ms_per_step", 30000.0)),
            total_timeout_ms=float(data.get("total_timeout_ms", 300000.0)),
            consecutive_failure_limit=int(data.get("consecutive_failure_limit", 3)),
        )
        cfg.validate_bounds()
        return cfg


@dataclass
class LoopStepRecord:
    step_index: int
    state_at_start: LoopState
    state_at_end: LoopState
    tool_name: Optional[str]
    tool_args_summary: str
    outcome: str  # "ok" | "refused" | "error"
    tokens_consumed: int
    duration_ms: float
    error_message: Optional[str] = None
    recorded_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_index": self.step_index,
            "state_at_start": self.state_at_start.value,
            "state_at_end": self.state_at_end.value,
            "tool_name": self.tool_name,
            "tool_args_summary": mask_secrets(self.tool_args_summary),
            "outcome": self.outcome,
            "tokens_consumed": self.tokens_consumed,
            "duration_ms": self.duration_ms,
            "error_message": mask_secrets(self.error_message) if self.error_message else None,
            "recorded_at_utc": self.recorded_at_utc,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LoopStepRecord":
        return cls(
            step_index=int(data["step_index"]),
            state_at_start=LoopState(data["state_at_start"]),
            state_at_end=LoopState(data["state_at_end"]),
            tool_name=data.get("tool_name"),
            tool_args_summary=str(data.get("tool_args_summary", "")),
            outcome=str(data.get("outcome", "ok")),
            tokens_consumed=int(data.get("tokens_consumed", 0)),
            duration_ms=float(data.get("duration_ms", 0.0)),
            error_message=data.get("error_message"),
            recorded_at_utc=data.get("recorded_at_utc", datetime.now(timezone.utc).isoformat()),
        )


@dataclass
class LoopSnapshot:
    loop_id: str
    current_state: LoopState
    current_iteration: int
    total_tokens_used: int
    total_tool_calls: int
    consecutive_failures: int
    is_terminated: bool
    terminal_reason: Optional[str] = None
    steps: List[LoopStepRecord] = field(default_factory=list)
    created_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def validate_invariants(self) -> None:
        """Enforces LOOPDATA-INV1 and LOOPDATA-INV2."""
        # LOOPDATA-INV1: monotonic contiguous step indices
        for i, step in enumerate(self.steps):
            if step.step_index != i:
                raise AssertionError(
                    f"{LOOPDATA_ERR_INVARIANT_VIOLATION}: LOOPDATA-INV1 violated at index {i}: "
                    f"step.step_index={step.step_index} != {i}"
                )

        # LOOPDATA-INV2: token non-negativity and conservation
        sum_tokens = sum(s.tokens_consumed for s in self.steps)
        if any(s.tokens_consumed < 0 for s in self.steps):
            raise AssertionError(f"{LOOPDATA_ERR_INVARIANT_VIOLATION}: negative tokens found in step record")
        if self.total_tokens_used != sum_tokens:
            raise AssertionError(
                f"{LOOPDATA_ERR_INVARIANT_VIOLATION}: LOOPDATA-INV2 violated: "
                f"total_tokens_used ({self.total_tokens_used}) != sum(steps.tokens) ({sum_tokens})"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "loop_id": self.loop_id,
            "current_state": self.current_state.value,
            "current_iteration": self.current_iteration,
            "total_tokens_used": self.total_tokens_used,
            "total_tool_calls": self.total_tool_calls,
            "consecutive_failures": self.consecutive_failures,
            "is_terminated": self.is_terminated,
            "terminal_reason": self.terminal_reason,
            "steps": [s.to_dict() for s in self.steps],
            "created_at_utc": self.created_at_utc,
            "updated_at_utc": self.updated_at_utc,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LoopSnapshot":
        steps = [LoopStepRecord.from_dict(s) for s in data.get("steps", [])]
        snap = cls(
            loop_id=str(data["loop_id"]),
            current_state=LoopState(data["current_state"]),
            current_iteration=int(data.get("current_iteration", 0)),
            total_tokens_used=int(data.get("total_tokens_used", 0)),
            total_tool_calls=int(data.get("total_tool_calls", 0)),
            consecutive_failures=int(data.get("consecutive_failures", 0)),
            is_terminated=bool(data.get("is_terminated", False)),
            terminal_reason=data.get("terminal_reason"),
            steps=steps,
            created_at_utc=data.get("created_at_utc", datetime.now(timezone.utc).isoformat()),
            updated_at_utc=data.get("updated_at_utc", datetime.now(timezone.utc).isoformat()),
        )
        snap.validate_invariants()
        return snap
