"""Comprehensive unit tests for Agent Loop Hardening Core Service (T-03277).

Covers:
- Valid input & multi-turn progression
- Invalid input & boundary configurations
- Timeout watchdog triggers (LOOPSERV_ERR_TIMEOUT)
- Token and iteration ceiling circuit breakers
- Consecutive failures circuit breaker
- PoR capability token gating on all mutating paths
- Secret masking in tool arguments and error traces
"""

import time
import pytest
from agent_loop_grants import AllowAllGate
from aiosh_mcp.agent_loop_data_model import (
    LoopConfig,
    LoopState,
    LOOPDATA_ERR_BOUNDS_EXCEEDED,
)
from aiosh_mcp.agent_loop_service import (
    AgentLoopService,
    AgentLoopServiceError,
    LOOPSERV_ERR_ALREADY_EXISTS,
    LOOPSERV_ERR_NOT_FOUND,
    LOOPSERV_ERR_POLICY_REFUSED,
    LOOPSERV_ERR_TERMINATED,
    LOOPSERV_ERR_TIMEOUT,
    LOOPSERV_ERR_UNAUTHORIZED,
)


@pytest.fixture
def service():
    return AgentLoopService(gate=AllowAllGate())


def test_core_service_multi_turn_progression(service):
    """Verify multi-turn execution correctly accumulates steps and token metrics."""
    cfg = LoopConfig(loop_id="loop-unit-multi-01", max_iterations=10, max_total_tokens=5000)
    token = "por-token-valid-01"

    snap = service.start_loop(cfg, capability_token=token)
    assert snap.current_state == LoopState.OBSERVE
    assert snap.total_tokens_used == 0

    # Turn 1
    s1 = service.advance_turn(
        loop_id="loop-unit-multi-01",
        action_intent="List directory contents",
        tool_name="aios.fs.read",
        tool_args={"path": "src/"},
        tokens_consumed=80,
        capability_token=token,
    )
    assert s1.step_index == 0
    assert s1.outcome == "ok"

    # Turn 2
    s2 = service.advance_turn(
        loop_id="loop-unit-multi-01",
        action_intent="Run status command",
        tool_name="aios.process.list",
        tool_args={},
        tokens_consumed=120,
        capability_token=token,
    )
    assert s2.step_index == 1
    assert s2.outcome == "ok"

    updated = service.get_snapshot("loop-unit-multi-01")
    assert updated.current_iteration == 2
    assert updated.total_tokens_used == 200
    assert updated.total_tool_calls == 2
    assert len(updated.steps) == 2


def test_core_service_watchdog_timeout(service):
    """Verify watchdog trips into ABORTED with LOOPSERV_ERR_TIMEOUT when total_timeout_ms is breached.

    OBSERVE -> FAILED is not a legal FSM edge, so the timeout must terminate via ABORTED.
    """
    cfg = LoopConfig(
        loop_id="loop-unit-timeout-01",
        total_timeout_ms=5000.0,  # min allowed bound
    )
    token = "por-token-valid-02"

    service.start_loop(cfg, capability_token=token)

    # Artificially shift start time backwards to simulate timeout
    service._start_times["loop-unit-timeout-01"] = time.time() - 10.0

    with pytest.raises(AgentLoopServiceError) as exc:
        service.advance_turn(
            loop_id="loop-unit-timeout-01",
            action_intent="Action after timeout",
            capability_token=token,
        )
    assert LOOPSERV_ERR_TIMEOUT in str(exc.value)

    snap = service.get_snapshot("loop-unit-timeout-01")
    assert snap.is_terminated is True
    assert snap.current_state == LoopState.ABORTED
    assert "total timeout" in (snap.terminal_reason or "")


def test_core_service_circuit_breaker_consecutive_failures(service):
    """Verify circuit breaker trips into FAILED when consecutive errors reach limit."""
    cfg = LoopConfig(
        loop_id="loop-unit-circuit-01",
        consecutive_failure_limit=2,
    )
    token = "por-token-valid-03"

    service.start_loop(cfg, capability_token=token)

    # First turn: policy denied (refusal does not count as error)
    s1 = service.advance_turn(
        loop_id="loop-unit-circuit-01",
        action_intent="Attempt 1",
        policy_allowed=False,
        capability_token=token,
    )
    assert s1.outcome == "refused"
    snap = service.get_snapshot("loop-unit-circuit-01")
    assert not snap.is_terminated

    # Artificially inject error steps into snapshot to test circuit breaker threshold
    from aiosh_mcp.agent_loop_data_model import LoopStepRecord
    err_step1 = LoopStepRecord(
        step_index=1,
        state_at_start=LoopState.OBSERVE,
        state_at_end=LoopState.RECORD_STEP,
        tool_name="fail_tool",
        tool_args_summary="{}",
        outcome="error",
        tokens_consumed=10,
        duration_ms=5.0,
    )
    snap.record_step(err_step1, cfg)
    assert snap.consecutive_failures == 1

    err_step2 = LoopStepRecord(
        step_index=2,
        state_at_start=LoopState.OBSERVE,
        state_at_end=LoopState.RECORD_STEP,
        tool_name="fail_tool",
        tool_args_summary="{}",
        outcome="error",
        tokens_consumed=10,
        duration_ms=5.0,
    )
    snap.record_step(err_step2, cfg)
    assert snap.consecutive_failures == 2
    assert snap.is_terminated is True
    assert snap.current_state == LoopState.FAILED
    assert "consecutive failure limit reached" in (snap.terminal_reason or "")


def test_core_service_secret_masking(service):
    """Verify sensitive tokens in tool arguments are redacted during step recording."""
    cfg = LoopConfig(loop_id="loop-unit-sec-01")
    token = "por-token-valid-04"

    service.start_loop(cfg, capability_token=token)

    step = service.advance_turn(
        loop_id="loop-unit-sec-01",
        action_intent="Call with secret bearer token",
        tool_name="aios.fs.read",
        tool_args={"token": "Bearer sk-proj-12345678901234567890abcdef"},
        tokens_consumed=50,
        capability_token=token,
    )

    d = step.to_dict()
    assert "sk-proj-1234" not in d["tool_args_summary"]
    assert "[REDACTED_SECRET]" in d["tool_args_summary"]


@pytest.mark.parametrize(
    "method_name,args",
    [
        ("start_loop", [LoopConfig(loop_id="loop-unauth-01")]),
        ("advance_turn", ["loop-unauth-01", "intent"]),
        ("abort_loop", ["loop-unauth-01", "reason"]),
    ],
)
def test_core_service_unauthorized_token_rejection(service, method_name, args):
    """PoR Invariant I-2: All mutating methods must fail-closed when capability_token is empty or whitespace."""
    fn = getattr(service, method_name)
    with pytest.raises(AgentLoopServiceError) as exc:
        fn(*args, capability_token="")
    assert LOOPSERV_ERR_UNAUTHORIZED in str(exc.value)

    with pytest.raises(AgentLoopServiceError) as exc:
        fn(*args, capability_token="   ")
    assert LOOPSERV_ERR_UNAUTHORIZED in str(exc.value)


def test_core_service_duplicate_loop_rejected(service):
    """Starting the same loop_id twice fails with LOOPSERV_ERR_ALREADY_EXISTS."""
    cfg = LoopConfig(loop_id="loop-unit-dup-01")
    service.start_loop(cfg, capability_token="por-token-dup")
    with pytest.raises(AgentLoopServiceError) as exc:
        service.start_loop(cfg, capability_token="por-token-dup")
    assert exc.value.code == LOOPSERV_ERR_ALREADY_EXISTS


def test_core_service_unknown_loop_not_found(service):
    """Every loop-addressed method reports LOOPSERV_ERR_NOT_FOUND for unknown ids."""
    for call in (
        lambda: service.get_snapshot("loop-missing-01"),
        lambda: service.advance_turn("loop-missing-01", "x", capability_token="t"),
        lambda: service.abort_loop("loop-missing-01", "x", capability_token="t"),
    ):
        with pytest.raises(AgentLoopServiceError) as exc:
            call()
        assert exc.value.code == LOOPSERV_ERR_NOT_FOUND


def test_core_service_terminated_loop_refuses_turns(service):
    """After abort, advance_turn raises LOOPSERV_ERR_TERMINATED and abort is idempotent."""
    cfg = LoopConfig(loop_id="loop-unit-term-01")
    service.start_loop(cfg, capability_token="t")
    snap = service.abort_loop("loop-unit-term-01", "operator stop", capability_token="t")
    assert snap.current_state == LoopState.ABORTED
    assert service.list_active_loops() == []
    again = service.abort_loop("loop-unit-term-01", "second stop", capability_token="t")
    assert again.terminal_reason == "operator stop"
    with pytest.raises(AgentLoopServiceError) as exc:
        service.advance_turn("loop-unit-term-01", "x", capability_token="t")
    assert exc.value.code == LOOPSERV_ERR_TERMINATED


def test_core_service_policy_refusal_skips_execution(service):
    """LOOPSERV-INV3: a refused step records outcome=refused and the policy error code."""
    service.start_loop(LoopConfig(loop_id="loop-unit-pol-01"), capability_token="t")
    step = service.advance_turn(
        "loop-unit-pol-01", "write", tool_name="fs.write", policy_allowed=False, capability_token="t"
    )
    assert step.outcome == "refused"
    assert LOOPSERV_ERR_POLICY_REFUSED in (step.error_message or "")
    assert step.state_at_start == LoopState.EVALUATE_POLICY


def test_core_service_iteration_ceiling_terminates(service):
    """Boundary: max_iterations=1 terminates the loop after exactly one turn."""
    service.start_loop(LoopConfig(loop_id="loop-unit-iter-01", max_iterations=1), capability_token="t")
    service.advance_turn("loop-unit-iter-01", "only turn", capability_token="t")
    snap = service.get_snapshot("loop-unit-iter-01")
    assert snap.is_terminated
    with pytest.raises(AgentLoopServiceError) as exc:
        service.advance_turn("loop-unit-iter-01", "too many", capability_token="t")
    assert exc.value.code == LOOPSERV_ERR_TERMINATED


@pytest.mark.parametrize(
    "kwargs",
    [
        {"loop_id": "short"},
        {"loop_id": "loop-bad-id-01; rm -rf /"},
        {"loop_id": "loop-bounds-01", "max_iterations": 0},
        {"loop_id": "loop-bounds-02", "max_iterations": 101},
        {"loop_id": "loop-bounds-03", "max_total_tokens": 99},
        {"loop_id": "loop-bounds-04", "total_timeout_ms": 4999.0},
    ],
)
def test_core_service_invalid_config_rejected(service, kwargs):
    """Invalid ids and out-of-range bounds are rejected and no loop is registered."""
    with pytest.raises(ValueError) as exc:
        service.start_loop(LoopConfig(**kwargs), capability_token="t")
    assert LOOPDATA_ERR_BOUNDS_EXCEEDED in str(exc.value)
    assert service.list_active_loops() == []
