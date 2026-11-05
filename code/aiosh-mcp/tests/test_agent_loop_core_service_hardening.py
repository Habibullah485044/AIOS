"""Hardening tests for Agent Loop Hardening Core Service (T-03280).

Failure modes must produce explicit, auditable errors and leave no open DB handles.
"""

import os
import threading

import pytest

from agent_loop_grants import AllowAllGate, audit_tools, mint_grant
from aiosh_mcp.agent_loop_data_model import LoopConfig, LoopState
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_service import (
    AgentLoopService,
    AgentLoopServiceError,
    LOOPSERV_ERR_AUDIT,
    LOOPSERV_ERR_CAPACITY,
    LOOPSERV_ERR_GATE_UNAVAILABLE,
    LOOPSERV_ERR_INVALID_INPUT,
    LOOPSERV_ERR_POLICY_REFUSED,
    LOOPSERV_ERR_TERMINATED,
    MAX_ACTION_INTENT_CHARS,
)


class FlakyGate(AllowAllGate):
    """Gate double whose audit or tool check can be made to fail on demand."""

    def __init__(self):
        super().__init__()
        self.fail_audit_on = set()
        self.fail_tool_check = False
        self.fail_redeem = False

    def redeem(self, grant_id, loop_id):
        if self.fail_redeem:
            raise OSError("database is locked")
        super().redeem(grant_id, loop_id)

    def tool_refusal(self, grant_id, tool_name, target=None):
        if self.fail_tool_check:
            raise OSError("disk I/O error")
        return None

    def audit(self, event, loop_id, grant_id, outcome, detail=None, args=None, classification=None,
              budget_guard=None):
        if event in self.fail_audit_on:
            raise OSError("audit ring unwritable")
        super().audit(event, loop_id, grant_id, outcome, detail, args, classification, budget_guard)


def test_start_audit_failure_registers_nothing():
    gate = FlakyGate()
    gate.fail_audit_on = {"start"}
    svc = AgentLoopService(gate=gate)
    with pytest.raises(AgentLoopServiceError) as exc:
        svc.start_loop(LoopConfig(loop_id="loop-hard-audit-01"), capability_token="t")
    assert exc.value.code == LOOPSERV_ERR_AUDIT
    assert svc.list_active_loops() == []


def test_step_audit_failure_terminates_loop():
    gate = FlakyGate()
    svc = AgentLoopService(gate=gate)
    svc.start_loop(LoopConfig(loop_id="loop-hard-audit-02"), capability_token="t")
    gate.fail_audit_on = {"step"}
    with pytest.raises(AgentLoopServiceError) as exc:
        svc.advance_turn("loop-hard-audit-02", "x", capability_token="t")
    assert exc.value.code == LOOPSERV_ERR_AUDIT
    snap = svc.get_snapshot("loop-hard-audit-02")
    assert snap.current_state == LoopState.ABORTED
    assert LOOPSERV_ERR_AUDIT in snap.terminal_reason
    gate.fail_audit_on = set()
    with pytest.raises(AgentLoopServiceError) as exc:
        svc.advance_turn("loop-hard-audit-02", "x", capability_token="t")
    assert exc.value.code == LOOPSERV_ERR_TERMINATED


def test_gate_unavailable_fails_closed():
    gate = FlakyGate()
    svc = AgentLoopService(gate=gate)
    gate.fail_redeem = True
    with pytest.raises(AgentLoopServiceError) as exc:
        svc.start_loop(LoopConfig(loop_id="loop-hard-gate-01"), capability_token="t")
    assert exc.value.code == LOOPSERV_ERR_GATE_UNAVAILABLE

    gate.fail_redeem = False
    svc.start_loop(LoopConfig(loop_id="loop-hard-gate-01"), capability_token="t")
    gate.fail_tool_check = True
    step = svc.advance_turn("loop-hard-gate-01", "x", tool_name="aios.fs.read", capability_token="t")
    assert step.outcome == "refused"
    assert LOOPSERV_ERR_POLICY_REFUSED in step.error_message
    assert LOOPSERV_ERR_GATE_UNAVAILABLE in step.error_message
    assert ("step", "loop-hard-gate-01", "refused") in gate.events


@pytest.mark.parametrize(
    "kwargs",
    [
        {"action_intent": "x" * (MAX_ACTION_INTENT_CHARS + 1)},
        {"action_intent": "x", "tool_name": "fs.write; rm -rf /"},
        {"action_intent": "x", "tool_name": "a" * 129},
        {"action_intent": "x", "tokens_consumed": -1},
        {"action_intent": "x", "tokens_consumed": True},
        {"action_intent": "x", "tokens_consumed": 1_000_001},
    ],
)
def test_turn_input_caps(kwargs):
    svc = AgentLoopService(gate=AllowAllGate())
    svc.start_loop(LoopConfig(loop_id="loop-hard-input-01"), capability_token="t")
    with pytest.raises(AgentLoopServiceError) as exc:
        svc.advance_turn("loop-hard-input-01", capability_token="t", **kwargs)
    assert exc.value.code == LOOPSERV_ERR_INVALID_INPUT
    assert svc.get_snapshot("loop-hard-input-01").steps == []


def test_abort_reason_cap():
    svc = AgentLoopService(gate=AllowAllGate())
    svc.start_loop(LoopConfig(loop_id="loop-hard-reason-01"), capability_token="t")
    with pytest.raises(AgentLoopServiceError) as exc:
        svc.abort_loop("loop-hard-reason-01", "r" * 1025, capability_token="t")
    assert exc.value.code == LOOPSERV_ERR_INVALID_INPUT


def test_capacity_evicts_terminated_then_refuses():
    svc = AgentLoopService(gate=AllowAllGate(), capacity=2)
    svc.start_loop(LoopConfig(loop_id="loop-hard-cap-01"), capability_token="t")
    svc.start_loop(LoopConfig(loop_id="loop-hard-cap-02"), capability_token="t")
    svc.abort_loop("loop-hard-cap-01", "done", capability_token="t")
    svc.start_loop(LoopConfig(loop_id="loop-hard-cap-03"), capability_token="t")  # evicts cap-01
    with pytest.raises(AgentLoopServiceError):
        svc.get_snapshot("loop-hard-cap-01")
    with pytest.raises(AgentLoopServiceError) as exc:
        svc.start_loop(LoopConfig(loop_id="loop-hard-cap-04"), capability_token="t")
    assert exc.value.code == LOOPSERV_ERR_CAPACITY


def test_concurrent_turns_keep_invariants():
    svc = AgentLoopService(gate=AllowAllGate())
    svc.start_loop(LoopConfig(loop_id="loop-hard-conc-01", max_iterations=100, max_total_tokens=1000000),
                   capability_token="t")
    errors = []

    def worker():
        for _ in range(10):
            try:
                svc.advance_turn("loop-hard-conc-01", "x", tokens_consumed=1, capability_token="t")
            except AgentLoopServiceError as exc:
                errors.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    snap = svc.get_snapshot("loop-hard-conc-01")
    snap.validate_invariants()
    assert len(snap.steps) + len(errors) == 80
    assert set(errors) <= {LOOPSERV_ERR_TERMINATED}
    assert [s.step_index for s in snap.steps] == list(range(len(snap.steps)))


def test_no_db_handles_leak_on_error_paths(tmp_path):
    """Windows refuses to delete an open SQLite file, so removal proves every handle was closed."""
    db = str(tmp_path / "audit.db")
    mint_grant(db, "gr_hard_leak", tools=["aios.agent_loop.start"])
    svc = AgentLoopService(gate=PepCapabilityGate(db))
    with pytest.raises(AgentLoopServiceError):
        svc.start_loop(LoopConfig(loop_id="loop-hard-leak-00"), capability_token="gr_unknown")
    svc.start_loop(LoopConfig(loop_id="loop-hard-leak-01"), capability_token="gr_hard_leak")
    refused = svc.advance_turn("loop-hard-leak-01", "x", tool_name="fs.write", capability_token="gr_hard_leak")
    assert refused.outcome == "refused"
    svc.abort_loop("loop-hard-leak-01", "done", capability_token="gr_hard_leak")
    assert [t for t, _ in audit_tools(db)][-1] == "aios.agent_loop.abort"
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(db + suffix):
            os.remove(db + suffix)
    assert not os.path.exists(db)
