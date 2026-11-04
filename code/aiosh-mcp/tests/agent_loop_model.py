"""Reference model + operation generator for agent-loop model-based fuzzing (T-03315 scaffold / T-03316 impl).

Spec: docs/tasks/evidence/T-03314-spec.md §2. The model predicts each operation's outcome
and audit effect from the *documented* contract (AUTOTEST-INV2):
SPEC-AGENT-LOOP-HARDENING-CORE-SERVICE §2/§5/§6 and the check order in T-03279/T-03280/T-03299.
The fuzzer runs the same operations against the real AgentLoopService + PepCapabilityGate
on a temp ring and compares after every step. Any failure is replayable from its seed.
"""

from __future__ import annotations

import copy
import random
import time
from contextlib import closing
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

#: Operation kinds the generator can emit (spec §2).
#: ``foreign_start``: a second service instance (another process / restarted server) on the same ring.
OP_KINDS = ("start", "advance", "abort", "complete", "revoke", "snapshot", "foreign_start")
DEFAULT_SEEDS = (1, 2, 3, 4, 5)
DEFAULT_OPS = 200
#: Wall-clock budget per seed; exceeding it is a reported failure, never a silent stop (T-03320).
DEFAULT_MAX_SECONDS = 120.0

START_TOOL = "aios.agent_loop.start"
SCOPED_TOOLS = (START_TOOL, "aios.fs.*")
NOSCOPE_GRANT = "gr_fuzz_noscope"      # minted, but cannot start loops
UNKNOWN_GRANT = "gr_fuzz_never_minted"  # never minted
OVERSIZE_ARGS = {"pad": "x" * 70_000}   # > MAX_ARGS_SUMMARY_BYTES


@dataclass(frozen=True)
class Op:
    """One generated operation; ``args`` are passed to the service method."""

    kind: str
    loop_id: str
    args: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Expectation:
    """Model prediction: error code (None = success) and audit tools appended, in order."""

    error_code: Optional[str]
    audit_tools: Tuple[str, ...] = ()


@dataclass
class FuzzReport:
    seed: int
    ops_run: int
    failures: List[str] = field(default_factory=list)
    log: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures


@dataclass
class _Loop:
    grant: str
    max_iter: int
    iteration: int = 0
    steps: int = 0
    terminated: bool = False


class LoopModel:
    """Spec-derived model of loops, grants and the audit ring."""

    def __init__(self) -> None:
        self.loops: Dict[str, _Loop] = {}
        self.claimed: set = set()                 # loop ids with a start row in the ring
        self.grants: Dict[str, Dict[str, Any]] = {NOSCOPE_GRANT: {"start": False, "redeemed": False,
                                                                   "revoked": False}}
        self.fresh = 0

    # ---- predictions -----------------------------------------------------------------
    def expect(self, op: Op) -> Expectation:
        a = op.args
        if op.kind == "revoke":
            return Expectation(None)
        if op.kind == "snapshot":
            return Expectation(None if op.loop_id in self.loops else "LOOPSERV_ERR_NOT_FOUND")
        if op.kind == "foreign_start":
            # Only ever drawn for ids already claimed in the ring: single-use ids, refused before
            # redemption, so the grant is not burned and nothing is written (T-03279 #2 fix).
            return Expectation("LOOPSERV_ERR_ALREADY_EXISTS")
        if op.kind == "start":
            if a["malformed"]:
                return Expectation("LOOPDATA_ERR_BOUNDS_EXCEEDED")
            if op.loop_id in self.loops or op.loop_id in self.claimed:
                return Expectation("LOOPSERV_ERR_ALREADY_EXISTS")
            g = self.grants.get(a["grant"])
            if g is None or not g["start"] or g["redeemed"] or g["revoked"]:
                return Expectation("LOOPSERV_ERR_UNAUTHORIZED")
            return Expectation(None, ("pep.capability.redeem", "aios.agent_loop.start"))
        if op.kind == "advance":
            # Input validation runs before the loop is looked up (T-03280 / T-03299 / #421).
            if a["tool_args"] is not None and a["tool_name"] is None:
                return Expectation("LOOPSERV_ERR_INVALID_INPUT")
            if a["tool_args"] is OVERSIZE_ARGS:
                return Expectation("LOOPSERV_ERR_INVALID_INPUT")
        loop = self.loops.get(op.loop_id)
        if loop is None:
            return Expectation("LOOPSERV_ERR_NOT_FOUND")
        if a["grant"] != loop.grant:
            return Expectation("LOOPSERV_ERR_UNAUTHORIZED")
        if op.kind == "abort":
            return Expectation(None, () if loop.terminated else ("aios.agent_loop.abort",))
        if loop.terminated:
            return Expectation("LOOPSERV_ERR_TERMINATED")
        if op.kind == "complete":
            if self.grants[loop.grant]["revoked"]:
                return Expectation("LOOPSERV_ERR_UNAUTHORIZED")
            return Expectation(None, ("aios.agent_loop.complete",))
        return Expectation(None, ("aios.agent_loop.step",))  # advance: ok or refused, one row either way

    def expected_step_outcome(self, op: Op) -> str:
        a = op.args
        loop = self.loops[op.loop_id]
        if not a["policy_allowed"] or self.grants[loop.grant]["revoked"]:
            return "refused"
        tool = a["tool_name"]
        return "ok" if tool is None or tool.startswith("aios.fs.") else "refused"

    # ---- state transition (only on the predicted outcome) -----------------------------
    def apply(self, op: Op, actual_error: Optional[str]) -> None:
        a = op.args
        if op.kind == "revoke":
            self.grants[a["grant"]]["revoked"] = True
            return
        if op.kind == "foreign_start":
            return
        if actual_error is not None or op.kind == "snapshot":
            return
        if op.kind == "start":
            self.grants[a["grant"]]["redeemed"] = True
            self.claimed.add(op.loop_id)
            self.loops[op.loop_id] = _Loop(grant=a["grant"], max_iter=a["max_iterations"])
            return
        loop = self.loops[op.loop_id]
        if op.kind in ("abort", "complete"):
            loop.terminated = True
            return
        loop.steps += 1
        loop.iteration += 1
        if loop.iteration >= loop.max_iter:   # iteration ceiling trips FAILED (no extra row)
            loop.terminated = True

    def new_grant(self) -> str:
        self.fresh += 1
        gid = f"gr_fuzz_{self.fresh:04d}"
        self.grants[gid] = {"start": True, "redeemed": False, "revoked": False}
        return gid


def _pick_loop(rng: random.Random, model: LoopModel) -> str:
    if model.loops and rng.random() < 0.85:
        return rng.choice(sorted(model.loops))
    return f"loop-fuzz-unknown-{rng.randrange(1000):03d}"


def next_op(rng: random.Random, model: LoopModel) -> Op:
    """Draws one operation biased towards the current model state."""
    kind = rng.choices(OP_KINDS, weights=(18, 45, 8, 8, 5, 6, 4))[0]
    if kind == "foreign_start" and model.claimed:
        return Op("foreign_start", rng.choice(sorted(model.claimed)), {"grant": model.new_grant()})
    if kind == "foreign_start":
        kind = "start"
    if kind == "start" or not model.loops:
        r = rng.random()
        if r < 0.08:
            lid = f"loop fuzz {rng.randrange(100)}"            # malformed (space)
        elif r < 0.18 and model.claimed:
            lid = rng.choice(sorted(model.claimed))            # reused id
        else:
            lid = f"loop-fuzz-{len(model.claimed) + rng.randrange(10_000):05d}"
        g = rng.random()
        if g < 0.70:
            grant = model.new_grant()
        elif g < 0.80:
            grant = NOSCOPE_GRANT
        elif g < 0.90:
            grant = UNKNOWN_GRANT
        else:
            spent = [k for k, v in model.grants.items() if v["redeemed"]]
            grant = rng.choice(sorted(spent)) if spent else model.new_grant()
        return Op("start", lid, {"grant": grant, "malformed": " " in lid,
                                 "max_iterations": rng.choice((3, 25))})
    lid = _pick_loop(rng, model)
    loop = model.loops.get(lid)
    bound = loop.grant if loop else UNKNOWN_GRANT
    grant = bound if rng.random() < 0.9 else rng.choice(sorted(model.grants))
    if kind == "revoke":
        live = sorted({l.grant for l in model.loops.values()})
        return Op("revoke", lid, {"grant": rng.choice(live)})
    if kind == "snapshot":
        return Op("snapshot", lid, {})
    if kind in ("abort", "complete"):
        return Op(kind, lid, {"grant": grant})
    tool = rng.choice(("aios.fs.read", "aios.fs.read", "fs.write", "github.delete_repo", None))
    r = rng.random()
    args = None if r < 0.4 else OVERSIZE_ARGS if r < 0.48 else {"path": "README.md", "n": rng.randrange(9)}
    return Op("advance", lid, {"grant": grant, "tool_name": tool, "tool_args": args,
                               "policy_allowed": rng.random() < 0.85})


def generate_ops(rng: random.Random, n: int, model: LoopModel) -> List[Op]:
    """A preview sequence, evolving a *copy* of the model along its own predictions."""
    sim = copy.deepcopy(model)
    ops = []
    for _ in range(n):
        op = next_op(rng, sim)
        sim.apply(op, sim.expect(op).error_code)
        ops.append(op)
    return ops


def _error_code(exc: BaseException) -> str:
    code = getattr(exc, "code", None)
    if code:
        return code
    msg = str(exc)
    return msg.split(":", 1)[0] if msg.startswith("LOOPDATA_ERR_") else f"UNEXPECTED:{type(exc).__name__}"


def run_and_check(seed: int, n_ops: int, db_path: str, max_seconds: float = DEFAULT_MAX_SECONDS) -> FuzzReport:
    """Runs ``n_ops`` model-checked operations against the real service on ``db_path``."""
    from agent_loop_grants import audit_tools, mint_grant, revoke_grant
    from aiosh_mcp import audit_client
    from aiosh_mcp.agent_loop_data_model import LoopConfig
    from aiosh_mcp.agent_loop_gate import PepCapabilityGate, read_loop_history
    from aiosh_mcp.agent_loop_service import AgentLoopService

    rng = random.Random(seed)
    model = LoopModel()
    report = FuzzReport(seed=seed, ops_run=0)
    mint_grant(db_path, NOSCOPE_GRANT, tools=["aios.fs.read"])
    svc = AgentLoopService(gate=PepCapabilityGate(db_path, busy_timeout_ms=5000), capacity=256)
    foreign = AgentLoopService(gate=PepCapabilityGate(db_path, busy_timeout_ms=5000), capacity=256)
    minted: set = {NOSCOPE_GRANT}
    frozen: Dict[str, int] = {}

    def fail(i: int, msg: str) -> None:
        report.failures.append(f"seed={seed} op#{i}: {msg}")

    deadline = time.monotonic() + max_seconds
    for i in range(n_ops):
        if time.monotonic() > deadline:
            fail(i, f"time budget of {max_seconds}s exceeded after {i} ops (possible hang or lock contention)")
            break
        op = next_op(rng, model)
        for gid in [op.args.get("grant")]:
            if gid and gid.startswith("gr_fuzz_0") and gid not in minted:
                mint_grant(db_path, gid, tools=list(SCOPED_TOOLS))
                minted.add(gid)
        report.log.append(f"#{i} {op.kind} {op.loop_id} {({k: v for k, v in op.args.items() if k != 'tool_args'})}")
        exp = model.expect(op)
        want_outcome = model.expected_step_outcome(op) if op.kind == "advance" and exp.error_code is None else None
        rows_before = len(audit_tools(db_path))
        actual: Optional[str] = None
        result: Any = None
        try:
            a = op.args
            if op.kind == "start":
                result = svc.start_loop(LoopConfig(loop_id=op.loop_id, max_iterations=a["max_iterations"]),
                                        capability_token=a["grant"])
            elif op.kind == "advance":
                result = svc.advance_turn(op.loop_id, "fuzz", tool_name=a["tool_name"], tool_args=a["tool_args"],
                                          policy_allowed=a["policy_allowed"], capability_token=a["grant"])
            elif op.kind == "abort":
                result = svc.abort_loop(op.loop_id, "fuzz abort", capability_token=a["grant"])
            elif op.kind == "complete":
                result = svc.complete_loop(op.loop_id, capability_token=a["grant"])
            elif op.kind == "foreign_start":
                result = foreign.start_loop(LoopConfig(loop_id=op.loop_id), capability_token=a["grant"])
            elif op.kind == "revoke":
                revoke_grant(db_path, a["grant"])
            else:
                result = svc.get_snapshot(op.loop_id)
        except Exception as exc:  # noqa: BLE001 - every outcome is compared with the model
            actual = _error_code(exc)
        report.ops_run += 1

        new_rows = tuple(t for t, _ in audit_tools(db_path)[rows_before:])
        if actual != exp.error_code:                                                     # M1
            fail(i, f"{op.kind} {op.loop_id}: expected {exp.error_code}, got {actual}")
        if new_rows != exp.audit_tools:                                                  # M2
            fail(i, f"{op.kind} {op.loop_id}: expected rows {exp.audit_tools}, got {new_rows}")
        if want_outcome is not None and actual is None and result.outcome != want_outcome:
            fail(i, f"advance {op.loop_id}: expected outcome {want_outcome}, got {result.outcome}")
        model.apply(op, actual if actual == exp.error_code else exp.error_code)

        for lid, mloop in model.loops.items():                                           # M3/M4
            snap = svc.get_snapshot(lid)
            try:
                snap.validate_invariants()
            except AssertionError as exc:
                fail(i, f"{lid}: invariant broken: {exc}")
            if snap.is_terminated != mloop.terminated:
                fail(i, f"{lid}: terminated={snap.is_terminated}, model says {mloop.terminated}")
            if mloop.terminated:
                frozen.setdefault(lid, len(snap.steps))
                if len(snap.steps) != frozen[lid]:
                    fail(i, f"{lid}: steps changed after termination")
        if len(report.failures) >= 5:
            break

    for lid in model.loops:                                                              # M5
        events = read_loop_history(db_path, lid, 1000)
        starts = [e for e in events if e["tool"] in ("aios.agent_loop.start", "aios.agent_loop.init")]
        if len(starts) != 1:
            report.failures.append(f"seed={seed} M5: {lid} has {len(starts)} start rows")
        if {e["args"].get("run_id") for e in events} != {svc.run_id(lid)}:
            report.failures.append(f"seed={seed} M5: {lid} rows carry foreign run_ids")
    with closing(audit_client.open_db(db_path)) as conn:
        if not audit_client.verify(conn)["ok"]:
            report.failures.append(f"seed={seed}: audit chain does not verify")
    return report
