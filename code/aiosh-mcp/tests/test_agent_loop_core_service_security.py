"""Security tests for Agent Loop Hardening Core Service (T-03279).

Each test is one abuse scenario from docs/tasks/evidence/T-03279-security.md, run
against the production PepCapabilityGate on an isolated audit DB.
"""

import pytest

from agent_loop_grants import audit_tools, mint_grant, revoke_grant, verify_chain
from aiosh_mcp.agent_loop_data_model import LoopConfig, LoopState
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_service import (
    AgentLoopService,
    AgentLoopServiceError,
    LOOPSERV_ERR_POLICY_REFUSED,
    LOOPSERV_ERR_UNAUTHORIZED,
)


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "audit.db")


@pytest.fixture
def service(db):
    return AgentLoopService(gate=PepCapabilityGate(db))


def test_s1_forged_token_rejected(service):
    """S1: an arbitrary non-empty string is not a capability (pre-T-03279 bypass)."""
    with pytest.raises(AgentLoopServiceError) as exc:
        service.start_loop(LoopConfig(loop_id="loop-sec-forge-01"), capability_token="anything")
    assert exc.value.code == LOOPSERV_ERR_UNAUTHORIZED
    assert service.list_active_loops() == []


def test_s2_single_use_grant_cannot_start_two_loops(service, db):
    """S2: replaying a redeemed single-use grant is refused."""
    mint_grant(db, "gr_sec_replay")
    service.start_loop(LoopConfig(loop_id="loop-sec-replay-01"), capability_token="gr_sec_replay")
    with pytest.raises(AgentLoopServiceError) as exc:
        service.start_loop(LoopConfig(loop_id="loop-sec-replay-02"), capability_token="gr_sec_replay")
    assert exc.value.code == LOOPSERV_ERR_UNAUTHORIZED
    assert "already redeemed" in exc.value.message


def test_s3_grant_without_start_scope_refused(service, db):
    """S3: a grant scoped only to other tools cannot start a loop."""
    mint_grant(db, "gr_sec_scope", tools=["aios.fs.read"])
    with pytest.raises(AgentLoopServiceError) as exc:
        service.start_loop(LoopConfig(loop_id="loop-sec-scope-01"), capability_token="gr_sec_scope")
    assert exc.value.code == LOOPSERV_ERR_UNAUTHORIZED


def test_s4_expired_and_revoked_grants_refused(service, db):
    """S4: expired or revoked grants cannot start a loop."""
    import datetime as dt
    mint_grant(db, "gr_sec_expired", expires_in=dt.timedelta(seconds=-1))
    mint_grant(db, "gr_sec_revoked")
    revoke_grant(db, "gr_sec_revoked")
    for gid in ("gr_sec_expired", "gr_sec_revoked"):
        with pytest.raises(AgentLoopServiceError) as exc:
            service.start_loop(LoopConfig(loop_id=f"loop-sec-{gid[7:]}-01"), capability_token=gid)
        assert exc.value.code == LOOPSERV_ERR_UNAUTHORIZED


def test_s5_loop_hijack_with_other_grant_refused(service, db):
    """S5: a valid grant for loop A cannot drive or abort loop B."""
    mint_grant(db, "gr_sec_a")
    mint_grant(db, "gr_sec_b")
    service.start_loop(LoopConfig(loop_id="loop-sec-own-a"), capability_token="gr_sec_a")
    service.start_loop(LoopConfig(loop_id="loop-sec-own-b"), capability_token="gr_sec_b")
    with pytest.raises(AgentLoopServiceError) as exc:
        service.advance_turn("loop-sec-own-a", "hijack", capability_token="gr_sec_b")
    assert exc.value.code == LOOPSERV_ERR_UNAUTHORIZED
    with pytest.raises(AgentLoopServiceError) as exc:
        service.abort_loop("loop-sec-own-a", "hijack", capability_token="gr_sec_b")
    assert exc.value.code == LOOPSERV_ERR_UNAUTHORIZED
    assert service.get_snapshot("loop-sec-own-a").current_state == LoopState.OBSERVE


def test_s6_caller_cannot_self_approve_out_of_scope_tool(service, db):
    """S6: policy_allowed=True does not widen the grant; out-of-scope tools are refused."""
    mint_grant(db, "gr_sec_policy", tools=["aios.agent_loop.start", "aios.fs.read"])
    service.start_loop(LoopConfig(loop_id="loop-sec-policy-01"), capability_token="gr_sec_policy")
    ok = service.advance_turn("loop-sec-policy-01", "read", tool_name="aios.fs.read",
                              policy_allowed=True, capability_token="gr_sec_policy")
    assert ok.outcome == "ok"
    bad = service.advance_turn("loop-sec-policy-01", "write", tool_name="fs.write",
                               policy_allowed=True, capability_token="gr_sec_policy")
    assert bad.outcome == "refused"
    assert LOOPSERV_ERR_POLICY_REFUSED in bad.error_message
    assert "not in grant scope" in bad.error_message


def test_s7_revocation_mid_loop_stops_tool_execution(service, db):
    """S7: revoking the bound grant refuses every later tool call."""
    mint_grant(db, "gr_sec_midrevoke")
    service.start_loop(LoopConfig(loop_id="loop-sec-midrev-01"), capability_token="gr_sec_midrevoke")
    revoke_grant(db, "gr_sec_midrevoke")
    step = service.advance_turn("loop-sec-midrev-01", "read", tool_name="aios.fs.read",
                                capability_token="gr_sec_midrevoke")
    assert step.outcome == "refused"
    assert "revoked" in step.error_message


def test_s8_every_state_change_writes_audit_row_and_chain_verifies(service, db):
    """S8: start/step/refused-step/abort each write an audit row; secrets are masked; chain valid."""
    mint_grant(db, "gr_sec_audit")
    service.start_loop(LoopConfig(loop_id="loop-sec-audit-01"), capability_token="gr_sec_audit")
    service.advance_turn("loop-sec-audit-01", "read", tool_name="aios.fs.read",
                         tool_args={"auth": "Bearer sk-abcdefghijklmnopqrstuvwxyz123456"},
                         capability_token="gr_sec_audit")
    service.advance_turn("loop-sec-audit-01", "no", tool_name="fs.write", policy_allowed=False,
                         capability_token="gr_sec_audit")
    service.abort_loop("loop-sec-audit-01", "stop", capability_token="gr_sec_audit")

    assert audit_tools(db) == [
        ("pep.capability.redeem", "ok"),
        ("aios.agent_loop.start", "ok"),
        ("aios.agent_loop.step", "ok"),
        ("aios.agent_loop.step", "refused"),
        ("aios.agent_loop.abort", "ok"),
    ]
    import sqlite3
    raw = "\n".join(r[0] for r in sqlite3.connect(db).execute("SELECT args_json FROM audit_ring"))
    assert "sk-abcdefghijklmnop" not in raw
    assert verify_chain(db).get("ok") is True


def test_s9_refused_start_burns_no_state(service, db):
    """S9: a refused start registers nothing and does not consume a valid grant for a bad config."""
    mint_grant(db, "gr_sec_bounds")
    with pytest.raises(ValueError):
        service.start_loop(LoopConfig(loop_id="loop-sec-bounds-01", max_iterations=0),
                           capability_token="gr_sec_bounds")
    snap = service.start_loop(LoopConfig(loop_id="loop-sec-bounds-01"), capability_token="gr_sec_bounds")
    assert snap.current_state == LoopState.OBSERVE
