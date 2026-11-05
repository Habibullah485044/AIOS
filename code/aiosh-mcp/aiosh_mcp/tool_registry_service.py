"""Tool Registry & Taxonomy core service (T-03375 scaffold).

Spec: docs/tasks/evidence/T-03374-spec.md. A pure decision service over the immutable catalog: for one tool
call it reports the canonical name, grant requirement, irreversibility and applicable scopes, and where the
catalog disagrees with the legacy name rules. Shadow mode (default) changes no enforcement; strict mode can
only tighten it (TOOLSVC-INV1..TOOLSVC-INV5).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from aiosh_mcp.tool_registry_data_model import ScopeKind, ToolCatalog

TOOLSVC_ERR_MODE = "TOOLSVC_ERR_MODE"
ENV_MODE = "AIOSH_TOOL_REGISTRY_MODE"
MODES = ("shadow", "strict")
DEFAULT_MODE = "shadow"
DISAGREEMENT_KINDS = ("unregistered", "grant", "irreversible", "scope")
MAX_UNREGISTERED_SAMPLES = 50
#: Structured stderr event name for a disagreement (no audit row: TOOLSVC-INV3).
LOG_EVENT = "tool_registry.disagreement"


class ToolServiceError(ValueError):
    """Invalid service configuration; ``code`` is a ``TOOLSVC_ERR_*`` value."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True)
class ToolDecision:
    """The service's answer for one call (spec §2)."""

    canonical: str
    registered: bool
    requires_grant: bool
    irreversible: bool
    scope_kinds: Tuple[ScopeKind, ...]
    disagreements: Tuple[str, ...]
    mode: str


class ToolRegistryService:
    """Pure, per-process decision service (spec §2)."""

    def __init__(self, catalog: Optional[ToolCatalog] = None, mode: Optional[str] = None) -> None:
        raise NotImplementedError("T-03376: ToolRegistryService")

    def decide(self, tool: Any, target: Any = None, classification: Optional[Dict[str, Any]] = None,
               require_grant: bool = False) -> ToolDecision:
        raise NotImplementedError("T-03376: ToolRegistryService.decide")

    def enforcement(self, decision: ToolDecision) -> Dict[str, Any]:
        raise NotImplementedError("T-03376: ToolRegistryService.enforcement")

    def stats(self) -> Dict[str, Any]:
        raise NotImplementedError("T-03376: ToolRegistryService.stats")


def service() -> ToolRegistryService:
    """Process-wide instance built once from the default catalog and the env mode."""
    raise NotImplementedError("T-03376: service")
