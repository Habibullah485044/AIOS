"""Hardening tests for Agent Loop Hardening Data Model (T-03270).

Verifies:
- Standard result envelope formatting
- Memory bounds & string truncation safeguards
- Maximum snapshot step capacity enforcement
- Registry capacity limits and LRU termination eviction
"""

import pytest
from aiosh_mcp.agent_loop_data_model import (
    create_initial,
    AgentLoopRegistry,
    LoopConfig,
    LoopResultEnvelope,
    LoopSnapshot,
    LoopState,
    LoopStepRecord,
    LOOPDATA_ERR_BOUNDS_EXCEEDED,
    LOOPDATA_ERR_NOT_FOUND,
    MAX_ARGS_SUMMARY_BYTES,
    MAX_ERROR_MSG_BYTES,
    MAX_SNAPSHOT_STEPS,
)


def test_hardening_result_envelope_structure():
    env_ok = LoopResultEnvelope(ok=True, data={"key": "val"})
    d_ok = env_ok.to_dict()
    assert d_ok["ok"] is True
    assert d_ok["data"] == {"key": "val"}
    assert "error" not in d_ok

    env_err = LoopResultEnvelope(
        ok=False,
        error="Something failed",
        error_code=LOOPDATA_ERR_NOT_FOUND,
    )
    d_err = env_err.to_dict()
    assert d_err["ok"] is False
    assert d_err["error"] == "Something failed"
    assert d_err["error_code"] == LOOPDATA_ERR_NOT_FOUND


def test_hardening_string_truncation():
    oversized_args = "x" * (MAX_ARGS_SUMMARY_BYTES + 500)
    oversized_err = "e" * (MAX_ERROR_MSG_BYTES + 300)

    step = LoopStepRecord(
        step_index=0,
        state_at_start=LoopState.PLAN,
        state_at_end=LoopState.RECORD_STEP,
        tool_name="cat",
        tool_args_summary=oversized_args,
        outcome="ok",
        tokens_consumed=10,
        duration_ms=5.0,
        error_message=oversized_err,
    )

    assert len(step.tool_args_summary) == MAX_ARGS_SUMMARY_BYTES + len(" [TRUNCATED]")
    assert step.tool_args_summary.endswith(" [TRUNCATED]")
    assert len(step.error_message) == MAX_ERROR_MSG_BYTES + len(" [TRUNCATED]")
    assert step.error_message.endswith(" [TRUNCATED]")


def test_hardening_max_snapshot_steps_limit():
    snap = create_initial("loop-max-steps-test")
    # Simulate a snapshot already having MAX_SNAPSHOT_STEPS
    snap.steps = [
        LoopStepRecord(
            step_index=i,
            state_at_start=LoopState.OBSERVE,
            state_at_end=LoopState.RECORD_STEP,
            tool_name="tool",
            tool_args_summary="{}",
            outcome="ok",
            tokens_consumed=1,
            duration_ms=1.0,
        )
        for i in range(MAX_SNAPSHOT_STEPS)
    ]
    snap.total_tokens_used = MAX_SNAPSHOT_STEPS

    next_step = LoopStepRecord(
        step_index=MAX_SNAPSHOT_STEPS,
        state_at_start=LoopState.OBSERVE,
        state_at_end=LoopState.RECORD_STEP,
        tool_name="tool",
        tool_args_summary="{}",
        outcome="ok",
        tokens_consumed=1,
        duration_ms=1.0,
    )

    with pytest.raises(ValueError) as exc:
        snap.record_step(next_step)
    assert LOOPDATA_ERR_BOUNDS_EXCEEDED in str(exc.value)


def test_hardening_registry_bounded_capacity_and_eviction():
    registry = AgentLoopRegistry(capacity=2)

    cfg1 = LoopConfig(loop_id="loop-reg-1")
    cfg2 = LoopConfig(loop_id="loop-reg-2")
    cfg3 = LoopConfig(loop_id="loop-reg-3")

    snap1 = registry.register_loop(cfg1)
    registry.register_loop(cfg2)

    # Both are active (not terminated) -> capacity exceeded raises error
    with pytest.raises(ValueError) as exc:
        registry.register_loop(cfg3)
    assert LOOPDATA_ERR_BOUNDS_EXCEEDED in str(exc.value)

    # Terminate loop 1 via valid FSM transition (INIT -> ABORTED)
    snap1.transition_to(LoopState.ABORTED, terminal_reason="Aborted")
    assert snap1.is_terminated is True

    # Registering loop 3 evicts loop 1
    registry.register_loop(cfg3)
    assert registry.get_loop("loop-reg-1") is None
    assert registry.get_loop("loop-reg-2") is not None
    assert registry.get_loop("loop-reg-3") is not None
