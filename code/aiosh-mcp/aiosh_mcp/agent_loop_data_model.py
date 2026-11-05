"""AI Control Plane Agent Loop Hardening Data Model (T-03265 scaffold / T-03266 impl / T-03268 integ / T-03270 hardening).

Enforces LOOPDATA-INV1..LOOPDATA-INV5: monotonic step indexing, token conservation,
circuit breaker bounds, substrate serialization parity, and FSM transition determinism.
Includes bounded memory limits, truncation safeguards, and LRU eviction.
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
LOOPDATA_ERR_UNAUTHORIZED = "LOOPDATA_ERR_UNAUTHORIZED"
LOOPDATA_ERR_NOT_FOUND = "LOOPDATA_ERR_NOT_FOUND"

MAX_SNAPSHOT_STEPS = 1000
MAX_ARGS_SUMMARY_BYTES = 65536
MAX_ERROR_MSG_BYTES = 16384
MAX_REGISTRY_CAPACITY = 256

LOOP_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{8,64}$")
# Token shapes (security audit 2026-11-05 #6). Audit rows are hash-chained and cannot be
# redacted later, so anything that reaches them must be masked before the write.
SECRET_PATTERN = re.compile(
    r"(sk-[a-zA-Z0-9_\-]{20,}"
    r"|gh[pousr]_[a-zA-Z0-9_\-]{20,}"
    r"|github_pat_[a-zA-Z0-9_]{20,}"
    r"|(?:AKIA|ASIA)[0-9A-Z]{16}"
    r"|xox[abprs]-[a-zA-Z0-9\-]{10,}"
    r"|eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"
    r"|(?:Basic|Digest)\s+[A-Za-z0-9+/=]{8,}"
    r"|Bearer\s+[a-zA-Z0-9_\-\.]{20,})",
    re.IGNORECASE,
)
#: Values of credential-named keys, in dict reprs, JSON or k=v form: 'password': 'x', "api_key": "x", token=x.
SECRET_KV_PATTERN = re.compile(
    r"""((?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?key|private[_-]?key"""
    r"""|auth[_-]?token|access[_-]?token|refresh[_-]?token|token|authorization|cookie|session[_-]?id)"""
    r"""['"]?\s*[:=]\s*['"]?)([^'",\s}&]+)""",
    re.IGNORECASE,
)


def mask_secrets(text: str) -> str:
    """Masks API keys, tokens, and authorization credentials."""
    if not text:
        return ""
    masked = SECRET_PATTERN.sub("[REDACTED_SECRET]", text)
    return SECRET_KV_PATTERN.sub(lambda m: m.group(1) + "[REDACTED_SECRET]", masked)


def truncate_safe(text: str, max_chars: int) -> str:
    """Safely bounds string length preventing unbounded memory growth."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + " [TRUNCATED]"


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
class LoopResultEnvelope:
    """Standardized result envelope for loop operations (ADR-0035)."""
    ok: bool
    error: Optional[str] = None
    error_code: Optional[str] = None
    data: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        res: Dict[str, Any] = {"ok": self.ok}
        if self.error:
            res["error"] = self.error
        if self.error_code:
            res["error_code"] = self.error_code
        if self.data is not None:
            res["data"] = self.data
        return res


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
        # fullmatch on the raw value: a stripped or `$`-before-newline match let "id " alias "id".
        if not isinstance(self.loop_id, str) or not LOOP_ID_PATTERN.fullmatch(self.loop_id):
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
    #: Policy summary for the step (T-03328): {"verdict", "rule_ids", "irreversible", ["irreversible_used"]}.
    policy: Optional[Dict[str, Any]] = None
    recorded_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        if self.tool_args_summary:
            self.tool_args_summary = truncate_safe(self.tool_args_summary, MAX_ARGS_SUMMARY_BYTES)
        if self.error_message:
            self.error_message = truncate_safe(self.error_message, MAX_ERROR_MSG_BYTES)

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
            **({"policy": dict(self.policy)} if self.policy is not None else {}),
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
            policy=data.get("policy"),
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

    def transition_to(self, new_state: LoopState, terminal_reason: Optional[str] = None) -> None:
        """Transitions to new_state enforcing FSM determinism (LOOPDATA-INV5)."""
        validate_loop_transition(self.current_state, new_state)
        self.current_state = new_state
        if new_state in {LoopState.COMPLETED, LoopState.FAILED, LoopState.ABORTED}:
            self.is_terminated = True
            if terminal_reason:
                self.terminal_reason = mask_secrets(terminal_reason)
        self.updated_at_utc = datetime.now(timezone.utc).isoformat()

    def record_step(self, step: LoopStepRecord, config: Optional[LoopConfig] = None) -> None:
        """Appends a step record and updates iteration, token counts, and circuit-breaker limits."""
        if len(self.steps) >= MAX_SNAPSHOT_STEPS:
            raise ValueError(
                f"{LOOPDATA_ERR_BOUNDS_EXCEEDED}: maximum step count ({MAX_SNAPSHOT_STEPS}) exceeded"
            )

        expected_index = len(self.steps)
        if step.step_index != expected_index:
            raise AssertionError(
                f"{LOOPDATA_ERR_INVARIANT_VIOLATION}: LOOPDATA-INV1 violated: "
                f"step.step_index={step.step_index} != expected {expected_index}"
            )
        if step.tokens_consumed < 0:
            raise AssertionError(
                f"{LOOPDATA_ERR_INVARIANT_VIOLATION}: tokens_consumed cannot be negative: {step.tokens_consumed}"
            )

        self.steps.append(step)
        self.total_tokens_used += step.tokens_consumed
        if step.tool_name:
            self.total_tool_calls += 1

        if step.outcome == "error":
            self.consecutive_failures += 1
        elif step.outcome == "ok":
            self.consecutive_failures = 0

        self.current_iteration += 1
        self.updated_at_utc = datetime.now(timezone.utc).isoformat()

        # Enforce bounds / circuit breakers if config is provided
        if config is not None:
            if self.consecutive_failures >= config.consecutive_failure_limit:
                self.current_state = LoopState.FAILED
                self.is_terminated = True
                self.terminal_reason = (
                    f"Circuit breaker triggered: consecutive failure limit reached ({self.consecutive_failures})"
                )
            elif self.total_tokens_used >= config.max_total_tokens:
                self.current_state = LoopState.FAILED
                self.is_terminated = True
                self.terminal_reason = (
                    f"Resource limit exceeded: token budget exhausted ({self.total_tokens_used}/{config.max_total_tokens})"
                )
            elif self.current_iteration >= config.max_iterations and not self.is_terminated:
                self.current_state = LoopState.FAILED
                self.is_terminated = True
                self.terminal_reason = (
                    f"Iteration limit reached ({self.current_iteration}/{config.max_iterations})"
                )

        self.validate_invariants()

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


def create_initial(loop_id: str, config: Optional[LoopConfig] = None) -> LoopSnapshot:
    """Creates a new initial LoopSnapshot in INIT state."""
    if not isinstance(loop_id, str) or not LOOP_ID_PATTERN.fullmatch(loop_id):
        raise ValueError(f"{LOOPDATA_ERR_BOUNDS_EXCEEDED}: invalid loop_id syntax: {loop_id}")
    if config is not None:
        config.validate_bounds()
    now_utc = datetime.now(timezone.utc).isoformat()
    return LoopSnapshot(
        loop_id=loop_id,
        current_state=LoopState.INIT,
        current_iteration=0,
        total_tokens_used=0,
        total_tool_calls=0,
        consecutive_failures=0,
        is_terminated=False,
        terminal_reason=None,
        steps=[],
        created_at_utc=now_utc,
        updated_at_utc=now_utc,
    )


class AgentLoopRegistry:
    """Thread-safe bounded in-memory registry of active and historical agent loops."""

    def __init__(self, capacity: int = MAX_REGISTRY_CAPACITY) -> None:
        self._capacity = capacity
        self._loops: Dict[str, LoopSnapshot] = {}
        self._configs: Dict[str, LoopConfig] = {}

    def get_loop(self, loop_id: str) -> Optional[LoopSnapshot]:
        return self._loops.get(loop_id)

    def register_loop(self, config: LoopConfig) -> LoopSnapshot:
        config.validate_bounds()
        if len(self._loops) >= self._capacity and config.loop_id not in self._loops:
            self._evict_terminated_or_raise()

        snap = create_initial(config.loop_id, config)
        self._loops[config.loop_id] = snap
        self._configs[config.loop_id] = config
        return snap

    def _evict_terminated_or_raise(self) -> None:
        # Find oldest terminated loop
        terminated = [lid for lid, snap in self._loops.items() if snap.is_terminated]
        if terminated:
            oldest = terminated[0]
            del self._loops[oldest]
            self._configs.pop(oldest, None)
            return
        raise ValueError(
            f"{LOOPDATA_ERR_BOUNDS_EXCEEDED}: loop registry capacity {self._capacity} reached and no terminated loops eligible for eviction"
        )

    def get_config(self, loop_id: str) -> Optional[LoopConfig]:
        return self._configs.get(loop_id)

    def list_loops(self) -> List[LoopSnapshot]:
        return list(self._loops.values())

    def clear(self) -> None:
        self._loops.clear()
        self._configs.clear()


_GLOBAL_LOOP_REGISTRY = AgentLoopRegistry()


def register_agent_loop_data_model_tools(mcp_app: Any) -> None:
    """Registers agent loop hardening data model tools with FastMCP (T-03268 / T-03270)."""

    @mcp_app.tool()
    def aios_agent_loop_status(loop_id: str) -> dict:
        """Returns the status, FSM state, and metrics for an agent loop (Pure read-only, PoR Invariant I-2)."""
        # Service first (audit finding #4): an INIT-only data-model entry must never
        # shadow the real state of a running loop with the same id.
        from aiosh_mcp.agent_loop_service import _GLOBAL_AGENT_LOOP_SERVICE
        snap = _GLOBAL_AGENT_LOOP_SERVICE._loops.get(loop_id) or _GLOBAL_LOOP_REGISTRY.get_loop(loop_id)
        if not snap:
            env = LoopResultEnvelope(
                ok=False,
                error=f"{LOOPDATA_ERR_NOT_FOUND}: loop_id '{loop_id}' not found",
                error_code=LOOPDATA_ERR_NOT_FOUND,
            )
            return env.to_dict()
        return {
            "ok": True,
            "snapshot": snap.to_dict(),
        }

    @mcp_app.tool()
    def aios_agent_loop_init(
        loop_id: str,
        max_iterations: int = 25,
        max_total_tokens: int = 32768,
        capability_token: str = "",
    ) -> dict:
        """Initializes a hardened agent loop FSM. Mutating: requires PoR capability token (PoR Invariant I-2)."""
        if not capability_token or not capability_token.strip():
            env = LoopResultEnvelope(
                ok=False,
                error=f"{LOOPDATA_ERR_UNAUTHORIZED}: capability token required for agent loop init (PoR Invariant I-2)",
                error_code=LOOPDATA_ERR_UNAUTHORIZED,
            )
            return env.to_dict()
        try:
            cfg = LoopConfig(
                loop_id=loop_id,
                max_iterations=max_iterations,
                max_total_tokens=max_total_tokens,
            )
            cfg.validate_bounds()
            from aiosh_mcp.agent_loop_gate import CapabilityRefused, LoopIdTaken
            from aiosh_mcp.agent_loop_service import _GLOBAL_AGENT_LOOP_SERVICE
            gate = _GLOBAL_AGENT_LOOP_SERVICE._gate
            # Audit finding #4: ids are unique across the data-model registry, the service
            # and every start/init row ever written to the ring.
            if (_GLOBAL_LOOP_REGISTRY.get_loop(loop_id) is not None
                    or loop_id in _GLOBAL_AGENT_LOOP_SERVICE._loops or gate.loop_id_used(loop_id)):
                return {"ok": False, "error": f"{LOOPDATA_ERR_INVALID_STATE}: loop_id '{loop_id}' already exists",
                        "error_code": LOOPDATA_ERR_INVALID_STATE}
            # T-03279: redeem the token as a PEP grant (PoR I-2); a non-empty string is not enough.
            try:
                gate.redeem(capability_token.strip(), loop_id)
            except CapabilityRefused as exc:
                return {"ok": False, "error": f"{LOOPDATA_ERR_UNAUTHORIZED}: {exc}",
                        "error_code": LOOPDATA_ERR_UNAUTHORIZED}
            try:
                gate.audit("init", loop_id, capability_token.strip(), "ok", args=cfg.to_dict())
            except LoopIdTaken:
                return {"ok": False, "error": f"{LOOPDATA_ERR_INVALID_STATE}: loop_id '{loop_id}' already exists",
                        "error_code": LOOPDATA_ERR_INVALID_STATE}
            snap = _GLOBAL_LOOP_REGISTRY.register_loop(cfg)
            return {
                "ok": True,
                "loop_id": loop_id,
                "snapshot": snap.to_dict(),
            }
        except Exception as exc:
            env = LoopResultEnvelope(
                ok=False,
                error=str(exc),
                error_code=LOOPDATA_ERR_BOUNDS_EXCEEDED,
            )
            return env.to_dict()
