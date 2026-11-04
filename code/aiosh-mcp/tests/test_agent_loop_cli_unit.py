"""Unit tests for the Agent Loop Hardening CLI surface (T-03287).

Valid input, invalid input, boundary values and the primary failure modes,
asserted through exit codes, JSON payloads and audit-ring contents.
"""

import json
import os

import pytest

from agent_loop_grants import audit_tools, mint_grant
from aiosh_mcp.agent_loop_cli import (
    EXIT_FAILURE,
    EXIT_SUCCESS,
    EXIT_UNAUTHORIZED,
    EXIT_USAGE,
    MAX_PLAN_BYTES,
    MAX_PLAN_TURNS,
    CliResult,
    dispatch_cli,
    main,
    render,
)
from aiosh_mcp.agent_loop_gate import PepCapabilityGate
from aiosh_mcp.agent_loop_service import AgentLoopService


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "audit.db")
    mint_grant(path, "gr_cli_unit", tools=["aios.agent_loop.start", "aios.fs.*"])
    return path


def _plan(tmp_path, doc, name="plan.json"):
    p = tmp_path / name
    p.write_text(doc if isinstance(doc, str) else json.dumps(doc), encoding="utf-8")
    return str(p)


def _turns(n, **extra):
    return {"turns": [dict({"action_intent": f"step {i}"}, **extra) for i in range(n)]}


def _run(db, plan, loop_id="loop-cli-unit-01", *extra):
    svc = AgentLoopService(gate=PepCapabilityGate(db))
    return dispatch_cli(["run", "--loop-id", loop_id, "--token", "gr_cli_unit", "--plan", plan, *extra],
                        service=svc, db_path=db)


# ---- valid input / boundaries -------------------------------------------------

@pytest.mark.parametrize("n", [1, MAX_PLAN_TURNS])
def test_validate_turn_count_boundaries_accepted(tmp_path, n):
    res = dispatch_cli(["validate", "--plan", _plan(tmp_path, _turns(n))])
    assert res.exit_code == EXIT_SUCCESS
    assert res.data == {"turns": n}


def test_run_stops_when_loop_terminates_mid_plan(tmp_path, db):
    """Boundary: max-iterations=1 with a 3-turn plan -> FAILED, 2 turns skipped, no complete row."""
    res = _run(db, _plan(tmp_path, _turns(3)), "loop-cli-unit-iter", "--max-iterations", "1")
    assert res.exit_code == EXIT_SUCCESS
    assert res.data["final_state"] == "FAILED"
    assert res.data["turns_skipped"] == 2
    assert "aios.agent_loop.complete" not in [t for t, _ in audit_tools(db)]


# ---- invalid input -------------------------------------------------------------

@pytest.mark.parametrize(
    "doc",
    [
        "{not json",
        [],
        {"turns": []},
        _turns(MAX_PLAN_TURNS + 1),
        {"turns": [{"action_intent": "x"}], "extra": 1},
        {"turns": [{"action_intent": ""}]},
        {"turns": [{"action_intent": "x", "surprise": True}]},
        {"turns": [{"action_intent": "x", "tool_name": "fs.write; rm -rf /"}]},
        {"turns": [{"action_intent": "x", "tool_args": "not-an-object"}]},
        {"turns": [{"action_intent": "x", "tokens_consumed": True}]},
        {"turns": [{"action_intent": "x", "tokens_consumed": -1}]},
        {"turns": [{"action_intent": "x", "policy_allowed": "yes"}]},
    ],
)
def test_invalid_plans_exit_usage(tmp_path, doc):
    res = dispatch_cli(["validate", "--plan", _plan(tmp_path, doc)])
    assert res.exit_code == EXIT_USAGE
    assert res.error_code == "LOOPCLI_ERR_PLAN"


def test_oversized_plan_rejected(tmp_path):
    big = json.dumps({"turns": [{"action_intent": "x" * 4000}] * 100})
    big += " " * (MAX_PLAN_BYTES + 1 - len(big))
    res = dispatch_cli(["validate", "--plan", _plan(tmp_path, big)])
    assert res.exit_code == EXIT_USAGE
    assert "exceeds" in res.error


def test_missing_plan_file(tmp_path):
    res = dispatch_cli(["validate", "--plan", str(tmp_path / "nope.json")])
    assert res.exit_code == EXIT_USAGE


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["bogus"],
        ["run", "--loop-id", "loop-cli-unit-01"],
        ["validate", "--plan", "a\0b"],
        ["history", "--loop-id", "loop-cli-unit-01", "--limit", "0"],
        ["history", "--loop-id", "loop-cli-unit-01", "--limit", "1001"],
        ["history", "--loop-id", "loop-cli-unit-01", "--limit", "many"],
    ],
)
def test_usage_errors(argv):
    assert dispatch_cli(argv).exit_code == EXIT_USAGE


def test_invalid_loop_id_rejected_before_grant_is_spent(tmp_path, db):
    """LOOPCLI-INV3: config errors exit 2 and leave the single-use grant redeemable."""
    plan = _plan(tmp_path, _turns(1))
    bad = _run(db, plan, "bad")
    assert bad.exit_code == EXIT_USAGE
    assert bad.error_code == "LOOPDATA_ERR_BOUNDS_EXCEEDED"
    assert audit_tools(db) == []
    assert _run(db, plan, "loop-cli-unit-ok").exit_code == EXIT_SUCCESS


def test_invalid_plan_does_not_spend_grant(tmp_path, db):
    bad = _run(db, _plan(tmp_path, {"turns": []}, "bad.json"))
    assert bad.exit_code == EXIT_USAGE
    assert audit_tools(db) == []


# ---- primary failure modes -----------------------------------------------------

def test_replayed_grant_exit_unauthorized(tmp_path, db):
    plan = _plan(tmp_path, _turns(1))
    assert _run(db, plan, "loop-cli-unit-a").exit_code == EXIT_SUCCESS
    res = _run(db, plan, "loop-cli-unit-b")
    assert res.exit_code == EXIT_UNAUTHORIZED
    assert "already redeemed" in res.error


def test_audit_failure_maps_to_exit_failure(tmp_path):
    from agent_loop_grants import AllowAllGate

    class BrokenAudit(AllowAllGate):
        def audit(self, *a, **k):
            raise OSError("ring unwritable")

    res = dispatch_cli(["run", "--loop-id", "loop-cli-unit-aud", "--token", "t",
                        "--plan", _plan(tmp_path, _turns(1))], service=AgentLoopService(gate=BrokenAudit()))
    assert res.exit_code == EXIT_FAILURE
    assert res.error_code == "LOOPSERV_ERR_AUDIT"


def test_history_on_missing_db_is_empty_and_creates_nothing(tmp_path):
    missing = str(tmp_path / "absent" / "audit.db")
    res = dispatch_cli(["history", "--loop-id", "loop-cli-unit-01"], db_path=missing)
    assert res.exit_code == EXIT_SUCCESS
    assert res.data["events"] == []
    assert not os.path.exists(missing)


def test_history_limit_and_isolation(tmp_path, db):
    _run(db, _plan(tmp_path, _turns(5)), "loop-cli-unit-hist")
    res = dispatch_cli(["history", "--loop-id", "loop-cli-unit-hist", "--limit", "2"], db_path=db)
    assert [e["tool"] for e in res.data["events"]] == ["aios.agent_loop.start", "aios.agent_loop.step"]
    assert all(e["args"]["loop_id"] == "loop-cli-unit-hist" for e in res.data["events"])


# ---- output contract (LOOPCLI-INV2 / INV4) ------------------------------------

def test_json_mode_exit_code_parity_on_failure(tmp_path, capsys):
    code = main(["validate", "--plan", str(tmp_path / "nope.json"), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == payload["exit_code"] == EXIT_USAGE
    assert payload["ok"] is False


def test_render_masks_secrets():
    res = CliResult(EXIT_FAILURE, "run", error_code="X", error="leak Bearer sk-abcdefghijklmnopqrstuvwxyz0123")
    for mode in (True, False):
        out = render(res, json_mode=mode)
        assert "sk-abcdefghijklmnop" not in out
        assert "[REDACTED_SECRET]" in out
