"""Comprehensive unit tests for Agent Loop Hardening Data Model (T-03267).

Covers valid input, invalid input, boundary conditions, invariant violations,
circuit-breaker triggers, and serialization integrity.
"""

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
    mask_secrets,
    validate_loop_transition,
)


def test_loop_state_terminal_immutability():
    """Verify that terminal states (COMPLETED, FAILED, ABORTED) cannot transition to any state."""
    for term in (LoopState.COMPLETED, LoopState.FAILED, LoopState.ABORTED):
        for candidate in LoopState:
            if candidate == term:
                continue
            with pytest.raises(ValueError) as exc:
                validate_loop_transition(term, candidate)
            assert LOOPDATA_ERR_INVALID_TRANSITION in str(exc.value)


@pytest.mark.parametrize(
    "field_name,bad_val",
    [
        ("loop_id", ""),
        ("loop_id", "short"),
        ("loop_id", "invalid!chars#here"),
        ("loop_id", "a" * 65),
        ("max_iterations", 0),
        ("max_iterations", 101),
        ("max_total_tokens", 99),
        ("max_total_tokens", 1000001),
        ("timeout_ms_per_step", 999.0),
        ("timeout_ms_per_step", 120001.0),
        ("total_timeout_ms", 4999.0),
        ("total_timeout_ms", 1800001.0),
        ("consecutive_failure_limit", 0),
        ("consecutive_failure_limit", 11),
    ],
)
def test_loop_config_boundaries(field_name, bad_val):
    """Verify exact upper and lower boundary rejections for LoopConfig."""
    kwargs = {
        "loop_id": "valid-loop-id",
        "max_iterations": 25,
        "max_total_tokens": 10000,
        "timeout_ms_per_step": 30000.0,
        "total_timeout_ms": 300000.0,
        "consecutive_failure_limit": 3,
    }
    kwargs[field_name] = bad_val
    cfg = LoopConfig(**kwargs)
    with pytest.raises(ValueError) as exc:
        cfg.validate_bounds()
    assert LOOPDATA_ERR_BOUNDS_EXCEEDED in str(exc.value)


def test_loop_config_exact_valid_boundaries():
    """Verify boundary edges (min and max) pass validation."""
    cfg_min = LoopConfig(
        loop_id="min-valid-8c",
        max_iterations=1,
        max_total_tokens=100,
        timeout_ms_per_step=1000.0,
        total_timeout_ms=5000.0,
        consecutive_failure_limit=1,
    )
    cfg_min.validate_bounds()

    cfg_max = LoopConfig(
        loop_id="m" * 64,
        max_iterations=100,
        max_total_tokens=1000000,
        timeout_ms_per_step=120000.0,
        total_timeout_ms=1800000.0,
        consecutive_failure_limit=10,
    )
    cfg_max.validate_bounds()


def test_step_record_negative_tokens_rejected():
    """LOOPDATA-INV2: Negative tokens consumed must be rejected."""
    snap = create_initial("loop-token-test")
    step = LoopStepRecord(
        step_index=0,
        state_at_start=LoopState.INIT,
        state_at_end=LoopState.OBSERVE,
        tool_name=None,
        tool_args_summary="",
        outcome="ok",
        tokens_consumed=-15,
        duration_ms=10.0,
    )
    with pytest.raises(AssertionError) as exc:
        snap.record_step(step)
    assert LOOPDATA_ERR_INVARIANT_VIOLATION in str(exc.value)


def test_step_record_non_monotonic_index_rejected():
    """LOOPDATA-INV1: Non-monotonic step index must fail."""
    snap = create_initial("loop-step-index-test")
    bad_step = LoopStepRecord(
        step_index=1,  # expected 0
        state_at_start=LoopState.INIT,
        state_at_end=LoopState.OBSERVE,
        tool_name=None,
        tool_args_summary="",
        outcome="ok",
        tokens_consumed=10,
        duration_ms=5.0,
    )
    with pytest.raises(AssertionError) as exc:
        snap.record_step(bad_step)
    assert LOOPDATA_ERR_INVARIANT_VIOLATION in str(exc.value)


def test_token_exhaustion_trips_failure():
    """Verify circuit breaker triggers FAILED state when total tokens exceed max_total_tokens."""
    cfg = LoopConfig(loop_id="loop-token-cap", max_total_tokens=200)
    snap = create_initial(cfg.loop_id, cfg)
    snap.transition_to(LoopState.OBSERVE)
    snap.transition_to(LoopState.PLAN)

    step = LoopStepRecord(
        step_index=0,
        state_at_start=LoopState.PLAN,
        state_at_end=LoopState.RECORD_STEP,
        tool_name="summarize",
        tool_args_summary="{}",
        outcome="ok",
        tokens_consumed=250,
        duration_ms=80.0,
    )
    snap.record_step(step, cfg)
    assert snap.is_terminated is True
    assert snap.current_state == LoopState.FAILED
    assert "token budget exhausted" in (snap.terminal_reason or "")


def test_consecutive_failure_reset_on_success():
    """Verify consecutive failure tally resets to 0 when a subsequent step succeeds."""
    cfg = LoopConfig(loop_id="loop-fail-reset", consecutive_failure_limit=3)
    snap = create_initial(cfg.loop_id, cfg)

    # Step 0: error
    step0 = LoopStepRecord(
        step_index=0,
        state_at_start=LoopState.INIT,
        state_at_end=LoopState.RECORD_STEP,
        tool_name="fail_tool",
        tool_args_summary="{}",
        outcome="error",
        tokens_consumed=10,
        duration_ms=5.0,
    )
    snap.record_step(step0, cfg)
    assert snap.consecutive_failures == 1

    # Step 1: success resets consecutive failure count
    step1 = LoopStepRecord(
        step_index=1,
        state_at_start=LoopState.RECORD_STEP,
        state_at_end=LoopState.RECORD_STEP,
        tool_name="ok_tool",
        tool_args_summary="{}",
        outcome="ok",
        tokens_consumed=15,
        duration_ms=6.0,
    )
    snap.record_step(step1, cfg)
    assert snap.consecutive_failures == 0
    assert not snap.is_terminated


def test_serialization_roundtrip_with_secret_masking():
    """LOOPDATA-INV4: Cross-substrate roundtrip preservation and secret masking."""
    cfg = LoopConfig(loop_id="loop-roundtrip-sec")
    snap = create_initial(cfg.loop_id, cfg)
    snap.transition_to(LoopState.OBSERVE)

    step = LoopStepRecord(
        step_index=0,
        state_at_start=LoopState.OBSERVE,
        state_at_end=LoopState.RECORD_STEP,
        tool_name="auth_call",
        tool_args_summary='{"auth": "Bearer ghp_abcdef123456789012345678"}',
        outcome="ok",
        tokens_consumed=40,
        duration_ms=25.0,
        error_message="Key sk-proj-12345678901234567890 expired",
    )
    snap.record_step(step, cfg)

    # Dict roundtrip
    d = snap.to_dict()
    assert "ghp_abcdef" not in d["steps"][0]["tool_args_summary"]
    assert "sk-proj-1234" not in (d["steps"][0]["error_message"] or "")
    assert "[REDACTED_SECRET]" in d["steps"][0]["tool_args_summary"]

    reconstructed = LoopSnapshot.from_dict(d)
    assert reconstructed.loop_id == snap.loop_id
    assert reconstructed.total_tokens_used == snap.total_tokens_used
    assert len(reconstructed.steps) == 1
    assert reconstructed.steps[0].step_index == 0
