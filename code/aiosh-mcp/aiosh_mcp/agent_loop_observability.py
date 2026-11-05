"""Agent Loop Hardening observability (T-03335 scaffold).

Spec: docs/tasks/evidence/T-03334-spec.md. Ring-derived metrics (cross-process, durable),
health classification and the module logger; LOOPOBS-INV1..LOOPOBS-INV3.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

#: Library logger: adds no handlers (the application configures logging).
logger = logging.getLogger("aiosh_mcp.agent_loop")

LOOPOBS_ERR_READ = "LOOPOBS_ERR_READ"
DEFAULT_WINDOW = 10_000
MAX_WINDOW = 100_000
REFUSAL_REASONS = ("constitution", "irreversible_budget", "scope", "caller", "target", "gate_unavailable", "other")
HEALTH_STATES = ("ok", "degraded", "failing")


def classify_refusal(outcome_detail: Optional[str]) -> str:
    """Maps a refused step's ``outcome_detail`` onto one of ``REFUSAL_REASONS``."""
    raise NotImplementedError("T-03336: classify_refusal")


def ring_metrics(db_path: Optional[str] = None, window: int = DEFAULT_WINDOW) -> Dict[str, Any]:
    """Read-only aggregates over the newest ``window`` agent-loop audit rows."""
    raise NotImplementedError("T-03336: ring_metrics")


def health(ring: Dict[str, Any], live: Optional[Dict[str, Any]] = None, config_degraded: bool = False) -> str:
    """``ok`` | ``degraded`` | ``failing`` (spec §5)."""
    raise NotImplementedError("T-03336: health")


def log_event(event: str, loop_id: str, run_id: Optional[str], outcome: str, reason: Optional[str] = None,
              level: int = logging.INFO) -> None:
    """One masked structured log line per consequential action (never grant ids or args)."""
    raise NotImplementedError("T-03336: log_event")
