"""Implementation unit tests for Agent Loop Hardening Core Service (T-03276).

Tests working behavior of AgentLoopService:
- start_loop lifecycle
- advance_turn progression through EVALUATE_POLICY, EXECUTE_TOOL, and RECORD_STEP
- policy refusal path (outcome="refused")
- abort_loop transition to ABORTED
- error handling for non-existent and terminated loops
"""

import pytest
from aiosh_mcp.agent_loop_data_model import LoopConfig, LoopState
from aiosh_mcp.agent_loop_service import (
    AgentLoopService,
    AgentLoopServiceError,
    LOOPSERV_ERR_ALREADY_EXISTS,
    LOOPSERV_ERR_NOT_FOUND,
    LOOPSERV_ERR_TERMINATED,
    LOOPSERV_ERR_UNAUTHORIZED,
)


def test_start_loop_working_lifecycle():
    service = AgentLoopService()
    cfg = LoopConfig(loop_id="loop-test-impl-01", max_iterations=10, max_total_tokens=4096)
    token = "por-valid-test-token"

    snap = service.start_loop(cfg, capability_token=token)
    assert snap.loop_id == "loop-test-impl-01"
    assert snap.current_state == LoopState.OBSERVE
    assert not snap.is_terminated
    assert len(snap.steps) == 0

    # Duplicate creation raises LOOPSERV_ERR_ALREADY_EXISTS
    with pytest.raises(AgentLoopServiceError) as exc:
        service.start_loop(cfg, capability_token=token)
    assert LOOPSERV_ERR_ALREADY_EXISTS in str(exc.value)


def test_advance_turn_happy_path():
    service = AgentLoopService()
    cfg = LoopConfig(loop_id="loop-test-impl-02", max_iterations=5, max_total_tokens=2048)
    token = "por-valid-test-token"

    service.start_loop(cfg, capability_token=token)

    step = service.advance_turn(
        loop_id="loop-test-impl-02",
        action_intent="Read config file",
        tool_name="aios.fs.read",
        tool_args={"path": "config.json"},
        tokens_consumed=120,
        policy_allowed=True,
        capability_token=token,
    )

    assert step.step_index == 0
    assert step.tool_name == "aios.fs.read"
    assert step.outcome == "ok"
    assert step.tokens_consumed == 120

    snap = service.get_snapshot("loop-test-impl-02")
    assert snap.current_iteration == 1
    assert snap.total_tokens_used == 120
    assert snap.current_state == LoopState.OBSERVE
    assert len(snap.steps) == 1


def test_advance_turn_policy_refusal():
    service = AgentLoopService()
    cfg = LoopConfig(loop_id="loop-test-impl-03", max_iterations=5)
    token = "por-valid-test-token"

    service.start_loop(cfg, capability_token=token)

    step = service.advance_turn(
        loop_id="loop-test-impl-03",
        action_intent="Execute unauthorized exploit",
        tool_name="pentest.nmap",
        tool_args={"target": "10.0.0.1"},
        tokens_consumed=30,
        policy_allowed=False,  # Policy denied
        capability_token=token,
    )

    assert step.step_index == 0
    assert step.outcome == "refused"
    assert step.tool_name == "pentest.nmap"
    assert "Policy evaluation refused" in (step.error_message or "")

    snap = service.get_snapshot("loop-test-impl-03")
    assert snap.current_iteration == 1
    assert snap.total_tokens_used == 30
    assert not snap.is_terminated


def test_abort_loop_and_terminated_rejection():
    service = AgentLoopService()
    cfg = LoopConfig(loop_id="loop-test-impl-04")
    token = "por-valid-test-token"

    service.start_loop(cfg, capability_token=token)
    aborted_snap = service.abort_loop("loop-test-impl-04", reason="Operator emergency stop", capability_token=token)

    assert aborted_snap.is_terminated is True
    assert aborted_snap.current_state == LoopState.ABORTED
    assert "Operator emergency stop" in (aborted_snap.terminal_reason or "")

    # Further turn on terminated loop must fail
    with pytest.raises(AgentLoopServiceError) as exc:
        service.advance_turn(
            "loop-test-impl-04",
            action_intent="Try after abort",
            capability_token=token,
        )
    assert LOOPSERV_ERR_TERMINATED in str(exc.value)
