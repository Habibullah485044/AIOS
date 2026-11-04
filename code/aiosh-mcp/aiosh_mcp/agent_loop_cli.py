"""AI Control Plane Agent Loop Hardening CLI Surface (T-03285 scaffold).

One-shot operator CLI over AgentLoopService (spec: docs/tasks/evidence/T-03284-spec.md):

    python -m aiosh_mcp.agent_loop_cli validate --plan plan.json
    python -m aiosh_mcp.agent_loop_cli run --loop-id ID --token GRANT --plan plan.json [--json]
    python -m aiosh_mcp.agent_loop_cli history --loop-id ID [--limit N] [--json]

Enforces LOOPCLI-INV1..LOOPCLI-INV4.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from aiosh_mcp.agent_loop_service import AgentLoopService

EXIT_SUCCESS: int = 0
EXIT_FAILURE: int = 1
EXIT_USAGE: int = 2
EXIT_UNAUTHORIZED: int = 3
EXIT_TIMEOUT: int = 4

MAX_PLAN_BYTES = 1024 * 1024
MAX_PLAN_TURNS = 100
MAX_HISTORY_LIMIT = 1000
DEFAULT_HISTORY_LIMIT = 100

LOOPCLI_ERR_USAGE = "LOOPCLI_ERR_USAGE"
LOOPCLI_ERR_PLAN = "LOOPCLI_ERR_PLAN"


@dataclass(frozen=True)
class PlanTurn:
    """One planned turn from a plan file."""

    action_intent: str
    tool_name: Optional[str] = None
    tool_args: Optional[Dict[str, Any]] = None
    tokens_consumed: int = 0
    policy_allowed: bool = True


@dataclass
class CliResult:
    """Standard CLI result (LOOPCLI-INV2): exit code plus the --json payload."""

    exit_code: int
    subcommand: str
    data: Optional[Dict[str, Any]] = None
    error_code: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError("T-03286: CliResult.to_dict")


class PlanError(ValueError):
    """Raised for an unreadable or invalid plan file (exit 2)."""


def load_plan(path: str) -> List[PlanTurn]:
    """Reads and validates a plan file (LOOPCLI-INV3: before any grant redemption)."""
    raise NotImplementedError("T-03286: load_plan")


def dispatch_cli(
    argv: List[str],
    service: Optional[AgentLoopService] = None,
    db_path: Optional[str] = None,
) -> CliResult:
    """Parses argv and runs one subcommand; never raises."""
    raise NotImplementedError("T-03286: dispatch_cli")


def render(result: CliResult, json_mode: bool) -> str:
    """Formats a result for stdout (masked, LOOPCLI-INV4)."""
    raise NotImplementedError("T-03286: render")


def main(argv: Optional[List[str]] = None) -> int:
    """Console entry point; returns the process exit code."""
    raise NotImplementedError("T-03286: main")


if __name__ == "__main__":
    raise SystemExit(main())
