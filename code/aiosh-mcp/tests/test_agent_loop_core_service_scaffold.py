"""Scaffold tests for Agent Loop Hardening Core Service (T-03275 / T-03276)."""

import pytest
from agent_loop_grants import AllowAllGate
from aiosh_mcp.agent_loop_data_model import LoopConfig
from aiosh_mcp.agent_loop_service import (
    AgentLoopService,
    AgentLoopServiceError,
    LOOPSERV_ERR_ALREADY_EXISTS,
    LOOPSERV_ERR_NOT_FOUND,
    LOOPSERV_ERR_UNAUTHORIZED,
)


def test_service_scaffold_initialization():
    service = AgentLoopService(gate=AllowAllGate())
    assert len(service.list_active_loops()) == 0

    with pytest.raises(AgentLoopServiceError) as exc:
        service.get_snapshot("nonexistent-loop")
    assert LOOPSERV_ERR_NOT_FOUND in str(exc.value)


def test_service_scaffold_por_token_enforcement():
    service = AgentLoopService(gate=AllowAllGate())
    cfg = LoopConfig(loop_id="loop-scaffold-01")

    # Missing capability token must fail with LOOPSERV_ERR_UNAUTHORIZED
    with pytest.raises(AgentLoopServiceError) as exc:
        service.start_loop(cfg, capability_token="")
    assert LOOPSERV_ERR_UNAUTHORIZED in str(exc.value)

    with pytest.raises(AgentLoopServiceError) as exc:
        service.advance_turn("loop-scaffold-01", "intent", capability_token="")
    assert LOOPSERV_ERR_UNAUTHORIZED in str(exc.value)

    with pytest.raises(AgentLoopServiceError) as exc:
        service.abort_loop("loop-scaffold-01", "operator abort", capability_token="")
    assert LOOPSERV_ERR_UNAUTHORIZED in str(exc.value)


def test_service_basic_lifecycle():
    service = AgentLoopService(gate=AllowAllGate())
    cfg = LoopConfig(loop_id="loop-scaffold-02")

    snap = service.start_loop(cfg, capability_token="por-valid-token")
    assert snap.loop_id == "loop-scaffold-02"

    step = service.advance_turn(
        "loop-scaffold-02",
        "search",
        capability_token="por-valid-token",
    )
    assert step.step_index == 0

    aborted = service.abort_loop(
        "loop-scaffold-02",
        "cancel",
        capability_token="por-valid-token",
    )
    assert aborted.is_terminated is True
