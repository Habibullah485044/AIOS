"""Reference model + operation generator for agent-loop model-based fuzzing (T-03315 scaffold).

Spec: docs/tasks/evidence/T-03314-spec.md §2. The model predicts each operation's outcome
and audit effect from the *spec* (AUTOTEST-INV2); the fuzzer runs the same operations
against the real AgentLoopService + PepCapabilityGate and compares after every step.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

#: Operation kinds the generator can emit (spec §2).
OP_KINDS = ("start", "advance", "abort", "complete", "revoke", "snapshot")
DEFAULT_SEEDS = (1, 2, 3, 4, 5)
DEFAULT_OPS = 200


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


class LoopModel:
    """Spec-derived model of loops, grants and the audit ring."""

    def expect(self, op: Op) -> Expectation:
        raise NotImplementedError("T-03316: LoopModel.expect")

    def apply(self, op: Op, actual_error: Optional[str]) -> None:
        raise NotImplementedError("T-03316: LoopModel.apply")


def generate_ops(rng: random.Random, n: int, model: LoopModel) -> List[Op]:
    raise NotImplementedError("T-03316: generate_ops")


def run_and_check(seed: int, n_ops: int, db_path: str) -> FuzzReport:
    raise NotImplementedError("T-03316: run_and_check")
