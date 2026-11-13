"""Tool Registry & Taxonomy security policy: the single policy point (T-03425 scaffold / T-03426 impl).

Spec: docs/tasks/evidence/T-03424-security-policy-specification.md. Dispatch and the agent loop ask this module, and only
this module, what the registry adds to a call: a grant requirement (dispatch) or irreversibility (agent loop). It can
only tighten (TOOLPOL-INV1), changes nothing in shadow mode (TOOLPOL-INV2), names itself and the catalog revision in a
refusal it caused (TOOLPOL-INV3), never raises (TOOLPOL-INV4) and is not configurable (TOOLPOL-INV6).
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from aiosh_mcp.tool_registry_data_model import ToolCatalog, default_catalog

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


#: A few catalogs per process at most (the default one, plus test catalogs); the object is kept so its id stays valid.
_REVISIONS: Dict[int, Tuple[ToolCatalog, str]] = {}
_MAX_CACHED_REVISIONS = 8
_LOCK = threading.Lock()
#: Surfaces whose registry failure has been announced (once per surface per process).
_LOGGED: set = set()
#: The exact stderr lines consumers printed before this module existed (TOOLPOL-INV2: shadow output unchanged).
_FAILURE_LINES = {
    "dispatch": lambda name, strict: (f"aiosh-mcp: tool registry unavailable in dispatch ({name}); "
                                      f"{'strict: grants required' if strict else 'legacy rules only'}"),
    "agent_loop": lambda name, strict: (f"aiosh-mcp: tool registry: unavailable in the agent loop ({name}); "
                                        f"{'strict: steps counted irreversible' if strict else 'legacy rules only'}"),
}


def policy_revision(catalog: Optional[ToolCatalog] = None) -> str:
    """Deterministic digest of the catalog's security fields (spec §2.1, TOOLPOL-INV5)."""
    cat = catalog if catalog is not None else default_catalog()
    with _LOCK:
        hit = _REVISIONS.get(id(cat))
        if hit is not None and hit[0] is cat:
            return hit[1]
    rows = sorted([e.canonical, e.effect.value, bool(e.irreversible), bool(e.requires_grant), e.scope_kind.value,
                   bool(e.open_world)] for e in cat.entries())
    blob = json.dumps(rows, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    rev = REVISION_PREFIX + hashlib.sha256(blob).hexdigest()[:REVISION_HEX_LEN]
    with _LOCK:
        if len(_REVISIONS) < _MAX_CACHED_REVISIONS:
            _REVISIONS[id(cat)] = (cat, rev)
    return rev


def _revision_or_empty(catalog: Optional[ToolCatalog] = None) -> str:
    try:
        return policy_revision(catalog)
    except Exception:
        return ""


def _intended_strict() -> bool:
    """The operator's intended mode; if even that cannot be read, assume strict (fail closed)."""
    try:
        from aiosh_mcp.tool_registry_service import intended_mode
        return intended_mode() == "strict"
    except Exception:
        return True


def _announce_failure(surface: str, exc: BaseException, strict: bool) -> None:
    with _LOCK:
        if surface in _LOGGED:
            return
        _LOGGED.add(surface)
    from aiosh_mcp.tool_registry_service import _stderr_line
    _stderr_line(_FAILURE_LINES[surface](type(exc).__name__, strict))


def evaluate(tool: Any, target: Any = None, *, surface: str, require_grant: bool = False,
             legacy_irreversible: bool = False, classification: Optional[Dict[str, Any]] = None) -> PolicyVerdict:
    """The registry's contribution to one call; OR-only, fail closed iff strict was intended (spec §2.3)."""
    if surface not in SURFACES:
        raise ValueError(f"surface must be one of {', '.join(SURFACES)}")
    require_grant = bool(require_grant)
    legacy_irreversible = bool(legacy_irreversible)
    try:
        from aiosh_mcp import tool_registry_service as trs
        svc = trs.service()
        decision = svc.decide(tool, target, classification=classification, require_grant=require_grant)
        trs.report(decision, tool, surface=surface)
        return _combine(svc, decision, require_grant, legacy_irreversible)
    except Exception as exc:  # never break a call; fail closed if strict was asked for (T-03379 #2, TOOLPOL-INV4)
        strict = _intended_strict()
        _announce_failure(surface, exc, strict)
        grant = True if strict else require_grant
        return PolicyVerdict(requires_grant=grant, irreversible=True if strict else legacy_irreversible,
                             registry_added_grant=grant and not require_grant,
                             mode="strict" if strict else "shadow", revision=_revision_or_empty(),
                             failure=type(exc).__name__)


def _combine(svc: Any, decision: Any, require_grant: bool, legacy_irreversible: bool) -> PolicyVerdict:
    """The single OR rule shared by evaluate() and preview(), so the two cannot drift (TOOLPOL-INV1)."""
    added = svc.enforcement(decision)                     # {} in shadow (TOOLSVC-INV2)
    grant = require_grant or bool(added.get("requires_grant"))
    irreversible = legacy_irreversible or bool(added.get("irreversible"))
    return PolicyVerdict(requires_grant=grant, irreversible=irreversible,
                         registry_added_grant=grant and not require_grant, mode=svc.mode,
                         revision=_revision_or_empty(getattr(svc, "_catalog", None)))


def preview(svc: Any, decision: Any, *, require_grant: bool = False) -> Dict[str, Any]:
    """What dispatch would enforce for ``decision`` under ``svc``'s mode (T-03428). Pure: no report line, no
    failure announcement, no process state; for the read-only decide surfaces (MCP tool and CLI)."""
    v = _combine(svc, decision, bool(require_grant), False)
    return {"policy_revision": v.revision, "enforced_requires_grant": v.requires_grant,
            "enforced_irreversible": v.irreversible, "registry_added_grant": v.registry_added_grant,
            "grant_reason_suffix": grant_reason_suffix(v)}


def grant_reason_suffix(verdict: PolicyVerdict) -> str:
    """Text appended to a grant refusal the registry caused; empty otherwise (spec §2.4, TOOLPOL-INV3)."""
    if not verdict.registry_added_grant:
        return ""
    if verdict.failure is not None:
        return " (tool registry unavailable, strict: fail closed)"
    return f" (tool registry strict, catalog {verdict.revision or 'unknown'})"


def reset_process_state() -> None:
    """Forget announced failures and cached revisions (tests; config is per process, like the service)."""
    with _LOCK:
        _LOGGED.clear()
        _REVISIONS.clear()
