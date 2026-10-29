"""Implementation unit tests for Agent Loop Hardening Data Model (T-03266)."""

import pytest
from aiosh_mcp.agent_loop_data_model import (
    create_initial,
    LoopConfig,
    LoopSnapshot,
    LoopState,
    LoopStepRecord,
    LOOPDATA_ERR_BOUNDS_EXCEEDED,
    LOOPDATA_ERR_INVALID_TRANSITION,
    LOOPDATA_ERR_INVARIANT_VIOLATION,
)


def test_create_initial():
    snap = create_initial("loop-session-01")
    assert snap.loop_id == "loop-session-01"
    assert snap.current_state == LoopState.INIT
    assert snap.current_iteration == 0
    assert snap.total_tokens_used == 0
    assert snap.total_tool_calls == 0
    assert snap.consecutive_failures == 0
    assert not snap.is_terminated
    assert len(snap.steps) == 0


def test_transition_to_lifecycle():
    snap = create_initial("loop-session-02")
    snap.transition_to(LoopState.OBSERVE)
    assert snap.current_state == LoopState.OBSERVE
    assert not snap.is_terminated

    snap.transition_to(LoopState.PLAN)
    assert snap.current_state == LoopState.PLAN

    snap.transition_to(LoopState.COMPLETED, terminal_reason="Goal fulfilled")
    assert snap.current_state == LoopState.COMPLETED
    assert snap.is_terminated is True
    assert snap.terminal_reason == "Goal fulfilled"

    # Terminal state cannot transition anywhere
    with pytest.raises(ValueError) as exc:
        snap.transition_to(LoopState.OBSERVE)
    assert LOOPDATA_ERR_INVALID_TRANSITION in str(exc.value)


def test_record_step_and_circuit_breaker():
    cfg = LoopConfig(
        loop_id="loop-session-03",
        max_iterations=3,
        max_total_tokens=500,
        consecutive_failure_limit=2,
    )
    snap = create_initial(cfg.loop_id, cfg)
    snap.transition_to(LoopState.OBSERVE)
    snap.transition_to(LoopState.PLAN)
    snap.transition_to(LoopState.EVALUATE_POLICY)
    snap.transition_to(LoopState.EXECUTE_TOOL)

    # Step 0: successful tool call
    step0 = LoopStepRecord(
        step_index=0,
        state_at_start=LoopState.EXECUTE_TOOL,
        state_at_end=LoopState.RECORD_STEP,
        tool_name="cat_file",
        tool_args_summary='{"path": "sample.txt"}',
        outcome="ok",
        tokens_consumed=150,
        duration_ms=45.0,
    )
    snap.record_step(step0, cfg)
    assert snap.total_tokens_used == 150
    assert snap.total_tool_calls == 1
    assert snap.consecutive_failures == 0
    assert snap.current_iteration == 1

    # Step 1: failure tool call
    step1 = LoopStepRecord(
        step_index=1,
        state_at_start=LoopState.RECORD_STEP,
        state_at_end=LoopState.RECORD_STEP,
        tool_name="unknown_tool",
        tool_args_summary="{}",
        outcome="error",
        tokens_consumed=50,
        duration_ms=10.0,
        error_message="Tool not found",
    )
    snap.record_step(step1, cfg)
    assert snap.total_tokens_used == 200
    assert snap.total_tool_calls == 2
    assert snap.consecutive_failures == 1
    assert not snap.is_terminated

    # Step 2: second consecutive failure -> triggers circuit breaker
    step2 = LoopStepRecord(
        step_index=2,
        state_at_start=LoopState.RECORD_STEP,
        state_at_end=LoopState.FAILED,
        tool_name="unknown_tool",
        tool_args_summary="{}",
        outcome="error",
        tokens_consumed=50,
        duration_ms=10.0,
        error_message="Tool not found again",
    )
    snap.record_step(step2, cfg)
    assert snap.total_tokens_used == 250
    assert snap.consecutive_failures == 2
    assert snap.is_terminated is True
    assert snap.current_state == LoopState.FAILED
    assert "Circuit breaker triggered: consecutive failure limit reached" in (snap.terminal_reason or "")
