"""Seeded model-based fuzz of the agent-loop service (T-03316; spec T-03314 §2).

Each seed runs AIOSH_LOOP_FUZZ_OPS (default 200) generated operations against the real
AgentLoopService + PepCapabilityGate on a temp ring and checks M1..M5 after every step.
A failure prints the seed and recent ops; rerun with AIOSH_LOOP_FUZZ_SEEDS=<seed>.
"""

import os
import random

import pytest

import agent_loop_model as m

SEEDS = [int(s) for s in os.environ.get("AIOSH_LOOP_FUZZ_SEEDS", ",".join(map(str, m.DEFAULT_SEEDS))).split(",")]
N_OPS = int(os.environ.get("AIOSH_LOOP_FUZZ_OPS", m.DEFAULT_OPS))


@pytest.mark.parametrize("seed", SEEDS)
def test_service_matches_reference_model(seed, tmp_path):
    report = m.run_and_check(seed, N_OPS, str(tmp_path / "audit.db"))
    assert report.ok, "\n".join(report.failures + ["--- last ops ---"] + report.log[-20:])
    assert report.ops_run == N_OPS


def test_generation_is_reproducible():
    a = m.generate_ops(random.Random(7), 50, m.LoopModel())
    b = m.generate_ops(random.Random(7), 50, m.LoopModel())
    assert a == b
    kinds = {op.kind for op in m.generate_ops(random.Random(7), 300, m.LoopModel())}
    assert kinds == set(m.OP_KINDS)
