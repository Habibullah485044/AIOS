"""Scaffold tests for Agent Loop Hardening Core Service (T-03275)."""

import pytest
from aiosh_mcp.agent_loop_data_model import LoopConfig
from aiosh_mcp.agent_loop_service import (
    AgentLoopService,
    AgentLoopServiceError,
    LOOPSERV_ERR_ALREADY_EXISTS,
    LOOPSERV_ERR_NOT_FOUND,
    LOOPSERV_ERR_UNAUTHORIZED,
)


def test_service_scaffold_initialization():
    service = AgentLoopService()
    assert len(service.list_active_loops()) == 0

    with pytest.raises(AgentLoopServiceError) as exc:
        service.get_snapshot("nonexistent-loop")
    assert LOOPSERV_ERR_NOT_FOUND in str(exc.value)


def test_service_scaffold_por_token_enforcement():
    service = AgentLoopService()
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


def test_service_scaffold_not_implemented():
    service = AgentLoopService()
    cfg = LoopConfig(loop_id="loop-scaffold-02")

    # Calling with valid capability token hits NotImplementedError in scaffold
    with pytest.raises(NotImplementedError):
        service.start_loop(cfg, capability_token="por-valid-token")

    with pytest.raises(NotImplementedError):
        service.advance_turn(
            "loop-scaffold-02",
            "search",
            capability_token="por-valid-token",
        )

    with pytest.raises(NotImplementedError):
        service.abort_loop(
            "loop-scaffold-02",
            "cancel",
            capability_token="por-valid-token",
        )
