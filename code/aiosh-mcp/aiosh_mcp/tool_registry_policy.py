"""Tool Registry & Taxonomy security policy: the single policy point (T-03425 scaffold).

Spec: docs/tasks/evidence/T-03424-security-policy-specification.md. Dispatch and the agent loop ask this module, and only
this module, what the registry adds to a call: a grant requirement (dispatch) or irreversibility (agent loop). It can
only tighten (TOOLPOL-INV1), changes nothing in shadow mode (TOOLPOL-INV2), names itself and the catalog revision in a
refusal it caused (TOOLPOL-INV3), never raises (TOOLPOL-INV4) and is not configurable (TOOLPOL-INV6).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from aiosh_mcp.tool_registry_data_model import ToolCatalog

#: Callers of evaluate(); anything else is a programming error.
SURFACES = ("dispatch", "agent_loop")
#: Revision prefix ("tool registry policy").
REVISION_PREFIX = "trp-"
REVISION_HEX_LEN = 16
#: The entry fields that decide enforcement; only these feed the revision (spec §2.1).
SECURITY_FIELDS = ("effect", "irreversible", "requires_grant", "scope_kind", "open_world")


@dataclass(frozen=True)
class PolicyVerdict:
    """What the registry policy says about one call (spec §2.2)."""

    requires_grant: bool
    irreversible: bool
    registry_added_grant: bool
    mode: str
    revision: str
    failure: Optional[str] = None


def policy_revision(catalog: Optional[ToolCatalog] = None) -> str:
    """Deterministic digest of the catalog's security fields (spec §2.1, TOOLPOL-INV5)."""
    raise NotImplementedError("T-03426: policy_revision")


def evaluate(tool: Any, target: Any = None, *, surface: str, require_grant: bool = False,
             legacy_irreversible: bool = False, classification: Optional[Dict[str, Any]] = None) -> PolicyVerdict:
    """The registry's contribution to one call; OR-only, fail closed iff strict was intended (spec §2.3)."""
    raise NotImplementedError("T-03426: evaluate")


def grant_reason_suffix(verdict: PolicyVerdict) -> str:
    """Text appended to a grant refusal the registry caused; empty otherwise (spec §2.4)."""
    raise NotImplementedError("T-03426: grant_reason_suffix")
