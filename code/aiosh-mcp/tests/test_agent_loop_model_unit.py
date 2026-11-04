"""Unit tests for the agent-loop reference model (T-03317).

The fuzzer is only as good as its model, so each documented rule the model encodes is
pinned here against hand-built states (valid input, invalid input, boundaries, and the
primary failure mode: a model that drifts from the spec).
"""

import random

import pytest

import agent_loop_model as m

LID = "loop-model-unit-01"


def model_with_loop(max_iter=3, revoked=False):
    model = m.LoopModel()
    g = model.new_grant()
    start = m.Op("start", LID, {"grant": g, "malformed": False, "max_iterations": max_iter})
    assert model.expect(start) == m.Expectation(None, ("pep.capability.redeem", "aios.agent_loop.start"))
    model.apply(start, None)
    if revoked:
        model.apply(m.Op("revoke", LID, {"grant": g}), None)
    return model, g


def adv(g, tool="aios.fs.read", args=None, allowed=True, lid=LID):
    return m.Op("advance", lid, {"grant": g, "tool_name": tool, "tool_args": args, "policy_allowed": allowed})


# ---- start ------------------------------------------------------------------------

@pytest.mark.parametrize("grant_state,code", [
    ({"start": True, "redeemed": True, "revoked": False}, "LOOPSERV_ERR_UNAUTHORIZED"),
    ({"start": True, "redeemed": False, "revoked": True}, "LOOPSERV_ERR_UNAUTHORIZED"),
    ({"start": False, "redeemed": False, "revoked": False}, "LOOPSERV_ERR_UNAUTHORIZED"),
])
def test_start_refusals_write_nothing(grant_state, code):
    model = m.LoopModel()
    model.grants["g"] = grant_state
    e = model.expect(m.Op("start", LID, {"grant": "g", "malformed": False, "max_iterations": 3}))
    assert e == m.Expectation(code)


def test_start_unknown_grant_and_malformed_id():
    model = m.LoopModel()
    assert model.expect(m.Op("start", LID, {"grant": m.UNKNOWN_GRANT, "malformed": False,
                                            "max_iterations": 3})).error_code == "LOOPSERV_ERR_UNAUTHORIZED"
    assert model.expect(m.Op("start", "loop bad", {"grant": model.new_grant(), "malformed": True,
                                                   "max_iterations": 3})).error_code == "LOOPDATA_ERR_BOUNDS_EXCEEDED"


def test_reused_id_refused_locally_and_from_a_foreign_service():
    model, _ = model_with_loop()
    again = m.Op("start", LID, {"grant": model.new_grant(), "malformed": False, "max_iterations": 3})
    assert model.expect(again).error_code == "LOOPSERV_ERR_ALREADY_EXISTS"
    assert model.expect(m.Op("foreign_start", LID, {"grant": model.new_grant()})) == \
        m.Expectation("LOOPSERV_ERR_ALREADY_EXISTS")


# ---- advance ----------------------------------------------------------------------

def test_input_validation_precedes_lookup():
    model = m.LoopModel()
    assert model.expect(adv("x", tool=None, args={"a": 1}, lid="loop-nowhere-01")).error_code == \
        "LOOPSERV_ERR_INVALID_INPUT"
    assert model.expect(adv("x", args=m.OVERSIZE_ARGS, lid="loop-nowhere-01")).error_code == \
        "LOOPSERV_ERR_INVALID_INPUT"
    assert model.expect(adv("x", lid="loop-nowhere-01")).error_code == "LOOPSERV_ERR_NOT_FOUND"


@pytest.mark.parametrize("tool,allowed,revoked,outcome", [
    ("aios.fs.read", True, False, "ok"),
    (None, True, False, "ok"),
    ("fs.write", True, False, "refused"),
    ("github.delete_repo", True, False, "refused"),   # glob segment boundary (#421)
    ("aios.fs.read", False, False, "refused"),
    ("aios.fs.read", True, True, "refused"),          # revoked mid-loop
])
def test_step_outcome_rules(tool, allowed, revoked, outcome):
    model, g = model_with_loop(revoked=revoked)
    op = adv(g, tool=tool, allowed=allowed)
    assert model.expect(op) == m.Expectation(None, ("aios.agent_loop.step",))
    assert model.expected_step_outcome(op) == outcome


def test_wrong_grant_is_unauthorized():
    model, _ = model_with_loop()
    assert model.expect(adv(model.new_grant())).error_code == "LOOPSERV_ERR_UNAUTHORIZED"


def test_iteration_ceiling_boundary():
    model, g = model_with_loop(max_iter=3)
    for i in range(3):
        op = adv(g)
        assert model.expect(op).error_code is None, i
        model.apply(op, None)
    assert model.loops[LID].terminated and model.loops[LID].steps == 3
    assert model.expect(adv(g)).error_code == "LOOPSERV_ERR_TERMINATED"


# ---- abort / complete ----------------------------------------------------------------

def test_abort_is_idempotent_and_complete_is_not():
    model, g = model_with_loop()
    abort = m.Op("abort", LID, {"grant": g})
    assert model.expect(abort) == m.Expectation(None, ("aios.agent_loop.abort",))
    model.apply(abort, None)
    assert model.expect(abort) == m.Expectation(None, ())
    assert model.expect(m.Op("complete", LID, {"grant": g})).error_code == "LOOPSERV_ERR_TERMINATED"


def test_complete_requires_live_grant_but_abort_does_not():
    model, g = model_with_loop(revoked=True)
    assert model.expect(m.Op("complete", LID, {"grant": g})).error_code == "LOOPSERV_ERR_UNAUTHORIZED"
    assert model.expect(m.Op("abort", LID, {"grant": g})).error_code is None


# ---- model hygiene ----------------------------------------------------------------------

def test_failed_ops_do_not_change_model_state():
    model, g = model_with_loop()
    before = (dict(model.loops[LID].__dict__), set(model.claimed))
    model.apply(adv(g), "LOOPSERV_ERR_UNAUTHORIZED")
    model.apply(m.Op("complete", LID, {"grant": g}), "LOOPSERV_ERR_TERMINATED")
    assert (dict(model.loops[LID].__dict__), set(model.claimed)) == before


def test_generate_ops_does_not_mutate_the_callers_model():
    model, _ = model_with_loop()
    snapshot = (len(model.loops), model.fresh)
    m.generate_ops(random.Random(3), 100, model)
    assert (len(model.loops), model.fresh) == snapshot
