"""Unit test scaffold for Agent Loop Hardening Data Model (T-03265)."""

import pytest
from aiosh_mcp.agent_loop_data_model import (
    LoopConfig,
    LoopSnapshot,
    LoopState,
    LoopStepRecord,
    LOOPDATA_ERR_BOUNDS_EXCEEDED,
    LOOPDATA_ERR_INVALID_TRANSITION,
    LOOPDATA_ERR_INVARIANT_VIOLATION,
    mask_secrets,
    validate_loop_transition,
)


def test_loop_state_enum_and_transitions():
    assert LoopState.INIT == "INIT"
    assert LoopState.COMPLETED == "COMPLETED"

    # Valid transitions
    validate_loop_transition(LoopState.INIT, LoopState.OBSERVE)
    validate_loop_transition(LoopState.OBSERVE, LoopState.PLAN)
    validate_loop_transition(LoopState.PLAN, LoopState.EVALUATE_POLICY)
    validate_loop_transition(LoopState.EVALUATE_POLICY, LoopState.EXECUTE_TOOL)
    validate_loop_transition(LoopState.EXECUTE_TOOL, LoopState.RECORD_STEP)
    validate_loop_transition(LoopState.RECORD_STEP, LoopState.COMPLETED)

    # Invalid transitions
    with pytest.raises(ValueError) as exc:
        validate_loop_transition(LoopState.INIT, LoopState.EXECUTE_TOOL)
    assert LOOPDATA_ERR_INVALID_TRANSITION in str(exc.value)

    with pytest.raises(ValueError) as exc:
        validate_loop_transition(LoopState.COMPLETED, LoopState.OBSERVE)
    assert LOOPDATA_ERR_INVALID_TRANSITION in str(exc.value)


def test_loop_config_bounds_and_serialization():
    cfg = LoopConfig(
        loop_id="loop-test-123",
        max_iterations=10,
        max_total_tokens=2048,
        timeout_ms_per_step=15000.0,
        total_timeout_ms=60000.0,
        consecutive_failure_limit=3,
    )
    cfg.validate_bounds()

    d = cfg.to_dict()
    assert d["loop_id"] == "loop-test-123"
    restored = LoopConfig.from_dict(d)
    assert restored.loop_id == cfg.loop_id
    assert restored.max_iterations == 10

    # Test bounds violations
    with pytest.raises(ValueError) as exc:
        bad_cfg = LoopConfig(loop_id="!bad!", max_iterations=10)
        bad_cfg.validate_bounds()
    assert LOOPDATA_ERR_BOUNDS_EXCEEDED in str(exc.value)

    with pytest.raises(ValueError) as exc:
        bad_cfg = LoopConfig(loop_id="loop-valid", max_iterations=200)
        bad_cfg.validate_bounds()
    assert LOOPDATA_ERR_BOUNDS_EXCEEDED in str(exc.value)


def test_loop_step_and_snapshot_invariants():
    step0 = LoopStepRecord(
        step_index=0,
        state_at_start=LoopState.OBSERVE,
        state_at_end=LoopState.PLAN,
        tool_name=None,
        tool_args_summary="",
        outcome="ok",
        tokens_consumed=100,
        duration_ms=45.0,
    )
    step1 = LoopStepRecord(
        step_index=1,
        state_at_start=LoopState.PLAN,
        state_at_end=LoopState.RECORD_STEP,
        tool_name="read_file",
        tool_args_summary='{"path": "foo.txt", "token": "Bearer sk-12345678901234567890"}',
        outcome="ok",
        tokens_consumed=150,
        duration_ms=120.0,
    )

    snapshot = LoopSnapshot(
        loop_id="loop-test-run",
        current_state=LoopState.RECORD_STEP,
        current_iteration=2,
        total_tokens_used=250,
        total_tool_calls=1,
        consecutive_failures=0,
        is_terminated=False,
        steps=[step0, step1],
    )
    snapshot.validate_invariants()

    # Serialization test
    d = snapshot.to_dict()
    assert d["total_tokens_used"] == 250
    # verify secret masking
    assert "Bearer [REDACTED_SECRET]" in d["steps"][1]["tool_args_summary"] or "[REDACTED_SECRET]" in d["steps"][1]["tool_args_summary"]

    # Invariant failure test: step index non-monotonic
    bad_step = LoopStepRecord(
        step_index=5,
        state_at_start=LoopState.OBSERVE,
        state_at_end=LoopState.PLAN,
        tool_name=None,
        tool_args_summary="",
        outcome="ok",
        tokens_consumed=50,
        duration_ms=10.0,
    )
    bad_snap = LoopSnapshot(
        loop_id="loop-bad",
        current_state=LoopState.OBSERVE,
        current_iteration=1,
        total_tokens_used=50,
        total_tool_calls=0,
        consecutive_failures=0,
        is_terminated=False,
        steps=[bad_step],
    )
    with pytest.raises(AssertionError) as exc:
        bad_snap.validate_invariants()
    assert LOOPDATA_ERR_INVARIANT_VIOLATION in str(exc.value)


def test_mask_secrets():
    raw = "My api key is sk-ant-api03-abcdef1234567890abcdef and github ghp_1234567890123456789012"
    masked = mask_secrets(raw)
    assert "sk-ant" not in masked
    assert "ghp_" not in masked
    assert "[REDACTED_SECRET]" in masked
