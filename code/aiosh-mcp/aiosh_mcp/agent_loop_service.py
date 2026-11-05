"""AI Control Plane Agent Loop Hardening Core Service (T-03275 scaffold / T-03276 impl / T-03278 integ / T-03279 sec / T-03280 hardening / T-03299 sec).

Enforces LOOPSERV-INV1..LOOPSERV-INV5: deterministic FSM progression, audit atomicity,
pre-execution policy evaluation, execution timeout watchdogs, and PoR capability gating.

Capability model (T-03279): ``start_loop`` redeems the capability token as a single-use
PEP grant whose ``scope.tools`` covers ``aios.agent_loop.start``; the loop is then bound
to that grant, and ``advance_turn``/``abort_loop`` must present the same grant id. Every
tool invocation is re-checked against the bound grant's ``scope.tools`` before execution,
so a caller-supplied ``policy_allowed=True`` can only narrow, never widen, what runs.

Failure model (T-03280): every failure surfaces as an ``AgentLoopServiceError`` with an
explicit code. The service fails closed: an unavailable gate refuses the start or the tool
call, and an audit write that fails after a state change terminates the loop (FAILED/ABORTED)
so no further unaudited turns can run.
"""

from __future__ import annotations

import hmac
import json
import secrets
import re
import threading
import time
from typing import Any, Dict, List, Optional, Protocol

from aiosh_mcp.agent_loop_data_model import (
    LoopResultEnvelope,
    create_initial,
    mask_secrets,
    LoopConfig,
    LoopSnapshot,
    LoopState,
    LoopStepRecord,
    MAX_ARGS_SUMMARY_BYTES,
    MAX_REGISTRY_CAPACITY,
)
from aiosh_mcp.agent_loop_gate import CapabilityRefused, LoopIdTaken, PepCapabilityGate
from aiosh_mcp.agent_loop_policy import LOOPPOL_ERR_IRREVERSIBLE_BUDGET, evaluate_step

LOOPSERV_ERR_NOT_FOUND = "LOOPSERV_ERR_NOT_FOUND"
LOOPSERV_ERR_ALREADY_EXISTS = "LOOPSERV_ERR_ALREADY_EXISTS"
LOOPSERV_ERR_TERMINATED = "LOOPSERV_ERR_TERMINATED"
LOOPSERV_ERR_UNAUTHORIZED = "LOOPSERV_ERR_UNAUTHORIZED"
LOOPSERV_ERR_POLICY_REFUSED = "LOOPSERV_ERR_POLICY_REFUSED"
LOOPSERV_ERR_TIMEOUT = "LOOPSERV_ERR_TIMEOUT"
LOOPSERV_ERR_CIRCUIT_BREAKER = "LOOPSERV_ERR_CIRCUIT_BREAKER"
LOOPSERV_ERR_INVALID_INPUT = "LOOPSERV_ERR_INVALID_INPUT"
LOOPSERV_ERR_CAPACITY = "LOOPSERV_ERR_CAPACITY"
LOOPSERV_ERR_AUDIT = "LOOPSERV_ERR_AUDIT"
LOOPSERV_ERR_GATE_UNAVAILABLE = "LOOPSERV_ERR_GATE_UNAVAILABLE"

MAX_ACTION_INTENT_CHARS = 4096
MAX_REASON_CHARS = 1024
MAX_TOKENS_PER_TURN = 1_000_000
MAX_TOOL_ARGS_DEPTH = 32
#: tool_args keys whose string value is the call's target for scope.paths / scope.networks.
TARGET_ARG_KEYS = ("target", "path", "host")
TOOL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")


class AgentLoopServiceError(Exception):
    """Base exception for Agent Loop Core Service failures."""

    def __init__(self, code: str, message: str, loop_id: Optional[str] = None):
        safe_msg = mask_secrets(message)
        super().__init__(f"{code}: {safe_msg}")
        self.code = code
        self.message = safe_msg
        self.loop_id = loop_id


class CapabilityGate(Protocol):
    """Redeems capability tokens, re-checks tool scope, and writes audit rows."""

    def redeem(self, grant_id: str, loop_id: str) -> None: ...

    def tool_refusal(self, grant_id: str, tool_name: Optional[str],
                     target: Optional[str] = None) -> Optional[str]: ...

    def loop_id_used(self, loop_id: str) -> bool: ...

    def irreversible_budget(self, grant_id: str) -> Optional[int]: ...

    def audit(self, event: str, loop_id: str, grant_id: Optional[str], outcome: str,
              detail: Optional[str] = None, args: Optional[Dict[str, Any]] = None) -> None: ...


class AgentLoopService:
    """Core Service orchestrating hardened agent loop state machines (LOOPSERV-INV1..LOOPSERV-INV5)."""

    def __init__(self, gate: Optional[CapabilityGate] = None, capacity: Optional[int] = None) -> None:
        self._gate: CapabilityGate = gate if gate is not None else PepCapabilityGate()
        if capacity is None:  # T-03308: operator-configurable, clamped to 1..MAX_REGISTRY_CAPACITY
            from aiosh_mcp.agent_loop_config import process_config
            capacity = int(process_config()["config"]["registry_capacity"])
        self._capacity = capacity
        self._lock = threading.RLock()
        self._loops: Dict[str, LoopSnapshot] = {}
        self._configs: Dict[str, LoopConfig] = {}
        self._start_times: Dict[str, float] = {}
        self._grants: Dict[str, str] = {}
        #: Random per-run id stamped on every audit row of a loop (audit finding #2).
        self._runs: Dict[str, str] = {}
        #: ok irreversible steps per loop, for scope.max_irreversible (T-03326, LOOPPOL-INV3).
        self._irreversible_used: Dict[str, int] = {}

    @staticmethod
    def _require_token(capability_token: str, loop_id: Optional[str], action: str) -> str:
        if not capability_token or not capability_token.strip():
            raise AgentLoopServiceError(
                LOOPSERV_ERR_UNAUTHORIZED,
                f"Capability token required to {action} agent loop (PoR Invariant I-2)",
                loop_id,
            )
        return capability_token.strip()

    def _require_loop(self, loop_id: str) -> LoopSnapshot:
        snap = self._loops.get(loop_id)
        if not snap:
            raise AgentLoopServiceError(LOOPSERV_ERR_NOT_FOUND, f"Loop '{loop_id}' not found", loop_id)
        return snap

    def _require_binding(self, loop_id: str, token: str) -> str:
        """The presented token must be the grant that started this loop."""
        bound = self._grants.get(loop_id, "")
        if not bound or not hmac.compare_digest(bound.encode(), token.encode()):
            raise AgentLoopServiceError(
                LOOPSERV_ERR_UNAUTHORIZED,
                f"Capability token is not bound to loop '{loop_id}'",
                loop_id,
            )
        return bound

    def _audit_or_terminate(self, snap: LoopSnapshot, event: str, grant_id: str, outcome: str,
                            detail: Optional[str] = None, args: Optional[Dict[str, Any]] = None,
                            classification: Optional[Dict[str, Any]] = None) -> None:
        """Writes the audit row; on failure terminates the loop and raises LOOPSERV_ERR_AUDIT."""
        try:
            extra = {"classification": classification} if classification is not None else {}
            self._gate.audit(event, snap.loop_id, grant_id, outcome, detail=detail,
                             args={"run_id": self._runs.get(snap.loop_id), **(args or {})}, **extra)
        except Exception as exc:
            if not snap.is_terminated:
                snap.transition_to(LoopState.ABORTED,
                                   terminal_reason=f"{LOOPSERV_ERR_AUDIT}: audit write failed for '{event}'")
            raise AgentLoopServiceError(
                LOOPSERV_ERR_AUDIT, f"audit write failed for '{event}': {exc}", snap.loop_id
            ) from exc

    def _forget(self, loop_id: str) -> None:
        for table in (self._loops, self._configs, self._start_times, self._grants, self._runs,
                      self._irreversible_used):
            table.pop(loop_id, None)

    def _ensure_capacity(self, loop_id: str) -> None:
        """Evicts the oldest terminated loops; refuses the start if every slot is active."""
        if len(self._loops) < self._capacity:
            return
        for lid in [k for k, v in self._loops.items() if v.is_terminated]:
            self._forget(lid)
            if len(self._loops) < self._capacity:
                return
        raise AgentLoopServiceError(
            LOOPSERV_ERR_CAPACITY, f"active loop capacity ({self._capacity}) reached", loop_id
        )

    @staticmethod
    def _validate_tool_args(loop_id: str, tool_name: Optional[str],
                            tool_args: Optional[Dict[str, Any]]) -> None:
        """Rejects args the audit row could not record faithfully (T-03299 M2).

        Oversized args used to be truncated to MAX_ARGS_SUMMARY_BYTES in the step record and
        audit row, so a caller could hide the real arguments behind a benign prefix.
        """
        if tool_args is None:
            return
        if tool_name is None:
            raise AgentLoopServiceError(
                LOOPSERV_ERR_INVALID_INPUT, "tool_args given without tool_name", loop_id)
        if not isinstance(tool_args, dict):
            raise AgentLoopServiceError(LOOPSERV_ERR_INVALID_INPUT, "tool_args must be an object", loop_id)
        stack = [(tool_args, 1)]
        while stack:  # iterative: no RecursionError on hostile nesting
            node, depth = stack.pop()
            if depth > MAX_TOOL_ARGS_DEPTH:
                raise AgentLoopServiceError(
                    LOOPSERV_ERR_INVALID_INPUT, f"tool_args nested deeper than {MAX_TOOL_ARGS_DEPTH}", loop_id)
            children = node.values() if isinstance(node, dict) else node if isinstance(node, list) else ()
            stack.extend((c, depth + 1) for c in children if isinstance(c, (dict, list)))
        if len(str(tool_args)) > MAX_ARGS_SUMMARY_BYTES or                 len(json.dumps(tool_args, default=str)) > MAX_ARGS_SUMMARY_BYTES:
            raise AgentLoopServiceError(
                LOOPSERV_ERR_INVALID_INPUT, f"tool_args larger than {MAX_ARGS_SUMMARY_BYTES} bytes", loop_id)

    @staticmethod
    def _validate_turn_input(loop_id: str, action_intent: str, tool_name: Optional[str],
                             tokens_consumed: int) -> None:
        if not isinstance(action_intent, str) or len(action_intent) > MAX_ACTION_INTENT_CHARS:
            raise AgentLoopServiceError(
                LOOPSERV_ERR_INVALID_INPUT, f"action_intent must be a string of at most {MAX_ACTION_INTENT_CHARS} chars",
                loop_id)
        if tool_name is not None and not TOOL_NAME_PATTERN.match(tool_name):
            raise AgentLoopServiceError(
                LOOPSERV_ERR_INVALID_INPUT, "tool_name must match [A-Za-z0-9_.-]{1,128}", loop_id)
        if isinstance(tokens_consumed, bool) or not isinstance(tokens_consumed, int) \
                or not (0 <= tokens_consumed <= MAX_TOKENS_PER_TURN):
            raise AgentLoopServiceError(
                LOOPSERV_ERR_INVALID_INPUT, f"tokens_consumed must be an int in [0, {MAX_TOKENS_PER_TURN}]", loop_id)

    def start_loop(self, config: LoopConfig, capability_token: str) -> LoopSnapshot:
        """Redeems the grant, initializes the loop in INIT and moves to OBSERVE (LOOPSERV-INV5)."""
        token = self._require_token(capability_token, config.loop_id, "start")
        config.validate_bounds()
        with self._lock:
            if config.loop_id in self._loops:
                raise AgentLoopServiceError(
                    LOOPSERV_ERR_ALREADY_EXISTS,
                    f"Loop '{config.loop_id}' already exists",
                    config.loop_id,
                )
            self._ensure_capacity(config.loop_id)
            try:
                used = self._gate.loop_id_used(config.loop_id)
            except Exception as exc:
                raise AgentLoopServiceError(
                    LOOPSERV_ERR_GATE_UNAVAILABLE, f"capability gate unavailable: {exc}", config.loop_id
                ) from exc
            if used:
                # Checked before redemption so a reused id does not burn the grant.
                raise AgentLoopServiceError(
                    LOOPSERV_ERR_ALREADY_EXISTS,
                    f"Loop '{config.loop_id}' was already started (loop ids are single-use)",
                    config.loop_id,
                )
            try:
                self._gate.redeem(token, config.loop_id)
            except CapabilityRefused as exc:
                raise AgentLoopServiceError(LOOPSERV_ERR_UNAUTHORIZED, str(exc), config.loop_id) from exc
            except Exception as exc:
                raise AgentLoopServiceError(
                    LOOPSERV_ERR_GATE_UNAVAILABLE, f"capability gate unavailable: {exc}", config.loop_id
                ) from exc

            snap = create_initial(config.loop_id, config)
            snap.transition_to(LoopState.OBSERVE)
            run_id = secrets.token_hex(8)
            try:
                self._gate.audit("start", config.loop_id, token, "ok",
                                 args={"run_id": run_id, **config.to_dict()})
            except LoopIdTaken as exc:
                # Lost a concurrent start race for this id; the grant redemption is audited.
                raise AgentLoopServiceError(LOOPSERV_ERR_ALREADY_EXISTS, str(exc), config.loop_id) from exc
            except Exception as exc:
                # Not registered: an unaudited loop must not exist (grant stays redeemed, which is audited).
                raise AgentLoopServiceError(
                    LOOPSERV_ERR_AUDIT, f"audit write failed for 'start': {exc}", config.loop_id
                ) from exc

            self._loops[config.loop_id] = snap
            self._configs[config.loop_id] = config
            self._start_times[config.loop_id] = time.time()
            self._grants[config.loop_id] = token
            self._runs[config.loop_id] = run_id
            return snap

    def run_id(self, loop_id: str) -> str:
        """The random run id stamped on this loop's audit rows."""
        with self._lock:
            self._require_loop(loop_id)
            return self._runs.get(loop_id, "")

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
        token = self._require_token(capability_token, loop_id, "advance")
        self._validate_turn_input(loop_id, action_intent, tool_name, tokens_consumed)
        self._validate_tool_args(loop_id, tool_name, tool_args)
        with self._lock:
            return self._advance_locked(loop_id, token, tool_name, tool_args, tokens_consumed, policy_allowed)

    def _advance_locked(self, loop_id: str, token: str, tool_name: Optional[str],
                        tool_args: Optional[Dict[str, Any]], tokens_consumed: int,
                        policy_allowed: bool) -> LoopStepRecord:
        snap = self._require_loop(loop_id)
        grant_id = self._require_binding(loop_id, token)

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
                self._audit_or_terminate(snap, "timeout", grant_id, "error", detail=snap.terminal_reason)
                raise AgentLoopServiceError(
                    LOOPSERV_ERR_TIMEOUT,
                    f"Total timeout exceeded for loop '{loop_id}'",
                    loop_id,
                )

        # FSM sequencing: from current (OBSERVE or RECORD_STEP) to PLAN
        if snap.current_state == LoopState.RECORD_STEP:
            snap.transition_to(LoopState.OBSERVE)
        snap.transition_to(LoopState.PLAN)

        # LOOPSERV-INV3: Pre-Execution Policy Gate. The caller's verdict can only narrow
        # what the bound grant allows; it is never sufficient on its own.
        snap.transition_to(LoopState.EVALUATE_POLICY)
        # P1 caller verdict -> P2 constitution classifier -> P3 grant scope -> P4 irreversible budget (T-03324).
        target = next((v for k, v in (tool_args or {}).items()
                       if k in TARGET_ARG_KEYS and isinstance(v, str)), None)
        policy = evaluate_step(tool_name, target, tool_args or {})
        refusal = None if policy_allowed else "caller policy verdict"
        if refusal is None:
            refusal = policy.refused_reason
        if refusal is None:
            try:
                refusal = self._gate.tool_refusal(grant_id, tool_name, target)
            except Exception as exc:  # fail closed: an unreachable gate refuses the call
                refusal = f"{LOOPSERV_ERR_GATE_UNAVAILABLE}: {exc}"
        used = self._irreversible_used.get(loop_id, 0)
        budget: Optional[int] = None
        if refusal is None and policy.irreversible:
            try:
                budget = self._gate.irreversible_budget(grant_id)
            except Exception as exc:
                refusal = f"{LOOPSERV_ERR_GATE_UNAVAILABLE}: {exc}"
            if refusal is None and budget is not None and used >= budget:
                refusal = f"{LOOPPOL_ERR_IRREVERSIBLE_BUDGET}: used {used} of {budget}"
        policy_args = {"irreversible": policy.irreversible}
        if budget is not None:
            policy_args["irreversible_used"] = used + (1 if refusal is None else 0)
        # Surfaced on the step (MCP advance / CLI run / snapshot), T-03328.
        step_policy = {"verdict": policy.classification.get("classify_overall_verdict", "ok"),
                       "rule_ids": list(policy.classification.get("classify_rule_ids") or []), **policy_args}

        args_str = str(tool_args or {})
        start_state = LoopState.EVALUATE_POLICY

        if refusal is not None:
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
                error_message=f"{LOOPSERV_ERR_POLICY_REFUSED}: Policy evaluation refused tool invocation: {refusal}",
                policy=step_policy,
            )
            snap.record_step(step, config)
            self._audit_or_terminate(snap, "step", grant_id, "refused", detail=step.error_message,
                                     args={"step_index": step.step_index, "tool_name": tool_name, **policy_args},
                                     classification=policy.classification)
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
            policy=step_policy,
        )
        snap.record_step(step, config)
        if policy.irreversible:
            self._irreversible_used[loop_id] = used + 1
        self._audit_or_terminate(snap, "step", grant_id, "ok",
                                 args={"step_index": step.step_index, "tool_name": tool_name,
                                       "tool_args": step.tool_args_summary, **policy_args},
                                 classification=policy.classification)
        if not snap.is_terminated:
            snap.transition_to(LoopState.OBSERVE)
        return step

    def abort_loop(self, loop_id: str, reason: str, capability_token: str = "") -> LoopSnapshot:
        """Transitions active loop directly to ABORTED state (LOOPSERV-INV5)."""
        token = self._require_token(capability_token, loop_id, "abort")
        if not isinstance(reason, str) or len(reason) > MAX_REASON_CHARS:
            raise AgentLoopServiceError(
                LOOPSERV_ERR_INVALID_INPUT, f"reason must be a string of at most {MAX_REASON_CHARS} chars", loop_id)
        with self._lock:
            snap = self._require_loop(loop_id)
            grant_id = self._require_binding(loop_id, token)

            if snap.is_terminated:
                return snap

            snap.transition_to(LoopState.ABORTED, terminal_reason=reason)
            self._audit_or_terminate(snap, "abort", grant_id, "ok", detail=snap.terminal_reason)
            return snap

    def complete_loop(self, loop_id: str, capability_token: str = "") -> LoopSnapshot:
        """Ends an active loop normally (OBSERVE -> COMPLETED), audited (T-03286)."""
        token = self._require_token(capability_token, loop_id, "complete")
        with self._lock:
            snap = self._require_loop(loop_id)
            grant_id = self._require_binding(loop_id, token)
            if snap.is_terminated:
                raise AgentLoopServiceError(
                    LOOPSERV_ERR_TERMINATED,
                    f"Loop '{loop_id}' is terminated ({snap.current_state.value}): {snap.terminal_reason}",
                    loop_id,
                )
            # Audit finding #5: completing is a state change, so the bound grant must still
            # be live and the loop must still be inside its total timeout.
            config = self._configs.get(loop_id)
            elapsed_ms = (time.time() - self._start_times.get(loop_id, time.time())) * 1000.0
            if config and elapsed_ms > config.total_timeout_ms:
                snap.transition_to(LoopState.ABORTED, terminal_reason=(
                    f"{LOOPSERV_ERR_TIMEOUT}: total timeout ({config.total_timeout_ms}ms) exceeded"))
                self._audit_or_terminate(snap, "timeout", grant_id, "error", detail=snap.terminal_reason)
                raise AgentLoopServiceError(LOOPSERV_ERR_TIMEOUT, f"Total timeout exceeded for loop '{loop_id}'",
                                            loop_id)
            try:
                refusal = self._gate.tool_refusal(grant_id, None)
            except Exception as exc:
                refusal = f"{LOOPSERV_ERR_GATE_UNAVAILABLE}: {exc}"
            if refusal is not None:
                raise AgentLoopServiceError(LOOPSERV_ERR_UNAUTHORIZED, f"cannot complete: {refusal}", loop_id)
            snap.transition_to(LoopState.COMPLETED, terminal_reason="completed")
            self._audit_or_terminate(snap, "complete", grant_id, "ok")
            return snap

    def get_snapshot(self, loop_id: str) -> LoopSnapshot:
        """Returns current loop snapshot. Pure read-only (0 capability tokens)."""
        with self._lock:
            return self._require_loop(loop_id)

    def list_active_loops(self) -> List[LoopSnapshot]:
        """Lists active non-terminated loops in memory."""
        with self._lock:
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
    """Compatibility entry point used by server.py; the tools live in agent_loop_mcp (T-03296)."""
    from aiosh_mcp.agent_loop_mcp import register_agent_loop_mcp_tools

    register_agent_loop_mcp_tools(mcp_app, service=service)
