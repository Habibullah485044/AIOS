"""Tool registry observability: ring-derived metrics and health (T-03435 scaffold; spec T-03434 §2.3).

AIOS-specific. Read-only over the hash-chained ``audit_ring`` (``mode=ro``); never creates the DB, never writes rows,
never writes to stdout (TOOLOBS-INV4/5/6). Bodies land in T-03436.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

DEFAULT_WINDOW = 10_000
MAX_WINDOW = 100_000
DEFAULT_QUERY_DEADLINE_S = 10.0
HEALTH_STATES = ("ok", "degraded", "failing")
#: Key cap for every ``by_tool`` map (TOOLOBS-INV3); further tools are counted under "other".
MAX_TOOL_KEYS = 64

TOOLOBS_ERR_WINDOW = "TOOLOBS_ERR_WINDOW"
TOOLOBS_ERR_READ = "TOOLOBS_ERR_READ"

#: ``outcome_detail`` markers of refusals the registry caused (T-03426 ``grant_reason_suffix``).
STRICT_MARKER = "(tool registry strict, catalog "
UNAVAILABLE_MARKER = "(tool registry unavailable, strict: fail closed)"
REDEEM_TOOL = "pep.capability.redeem"


class ObservabilityReadError(Exception):
    """The ring could not be read within the bounds (unreadable, locked, or past the deadline)."""


def ring_metrics(db_path: Optional[str] = None, window: int = DEFAULT_WINDOW,
                 deadline_s: float = DEFAULT_QUERY_DEADLINE_S) -> Dict[str, Any]:
    """Registry refusals and capability redemptions in the newest ``window`` ring rows (spec §2.3)."""
    raise NotImplementedError("tool_registry_observability.ring_metrics lands in T-03436")


def health(stats: Dict[str, Any]) -> str:
    """``ok`` / ``degraded`` / ``failing`` from an ``aios_tool_registry_stats`` payload (spec §2.3)."""
    raise NotImplementedError("tool_registry_observability.health lands in T-03436")
