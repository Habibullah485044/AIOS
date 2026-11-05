"""Agent Loop Hardening recovery & validation (T-03355 scaffold).

Spec: docs/tasks/evidence/T-03354-spec.md. Validates runs reconstructed from the audit ring
and honestly closes runs orphaned by a crash (LOOPREC-INV1..LOOPREC-INV3).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

RECOVER_TOOL = "aios.agent_loop.recover"
TERMINAL_EVENTS = ("abort", "complete", "timeout", "failed", "recovered")
DEFAULT_GRACE_S = 900
MAX_LISTED_RUNS = 1000
PROBLEM_KINDS = ("rows_after_terminal", "duplicate_start", "step_index_gap", "run_id_mixed",
                 "budget_exceeded", "missing_start")


def validate_ring(db_path: Optional[str] = None, grace_s: float = DEFAULT_GRACE_S,
                  live_runs: Iterable[str] = ()) -> Dict[str, Any]:
    """Read-only per-run report (spec §2)."""
    raise NotImplementedError("T-03356: validate_ring")


def recover_orphans(db_path: Optional[str], capability_token: str, grace_s: float = DEFAULT_GRACE_S,
                    live_runs: Iterable[str] = ()) -> Dict[str, Any]:
    """Grant-gated, idempotent: one ``aios.agent_loop.recovered`` row per orphaned run (spec §3)."""
    raise NotImplementedError("T-03356: recover_orphans")
