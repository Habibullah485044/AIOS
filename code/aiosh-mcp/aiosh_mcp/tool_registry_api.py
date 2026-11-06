"""Tool Registry & Taxonomy MCP API surface (T-03395 scaffold / T-03396 impl).

Spec: docs/tasks/evidence/T-03394-spec.md. Two more read-only tools (``aios_tool_registry_decide``,
``aios_tool_registry_stats``) and ``apply_catalog_annotations``, which sets every served tool's MCP
annotations from the catalog without ever making a tool look *less* careful (TOOLAPI-INV1..TOOLAPI-INV4).

MCP annotations are client hints (MCP 2025-06-18: untrusted unless the server is trusted). Some clients
skip confirmation prompts for ``readOnlyHint=true`` tools, so that hint is only granted under a strict
conjunction; every other hint can only move towards caution.
"""

from __future__ import annotations

import sys
from typing import Any, Dict, Optional, Tuple

from aiosh_mcp.tool_registry_data_model import (
    TOOLREG_ERR_UNAVAILABLE,
    Effect,
    ScopeKind,
    ToolRegistryError,
    default_catalog,
)
from aiosh_mcp.tool_registry_data_model import NameArg  # noqa: F401  (module-level arg type; PEP 563 strings)

DECIDE_TOOL = "aios_tool_registry_decide"
STATS_TOOL = "aios_tool_registry_stats"
#: Categories in which a read-only, grant-free entry may be advertised as readOnlyHint=true (spec §2).
READ_ONLY_HINT_CATEGORIES = ("audit", "agent_loop", "mcp_core", "model_backend", "fs.read", "service")
#: Parameters that disqualify a tool from readOnlyHint=true whatever the catalog says (T-03399):
#: a grant/token argument means a call can redeem (consume) a grant; a path argument means it can read
#: arbitrary files. Clients may auto-approve read-only tools, so neither may be advertised as read-only.
GRANT_PARAMS = ("grant_id", "caller_grant_id", "capability_token", "token")
PATH_PARAMS = ("path", "paths", "file", "files", "dir", "directory", "target_path")


def unsafe_for_read_only_hint(parameters: Any) -> bool:
    """True if a tool's input schema has a grant/token or path-like argument (T-03399 F1, F4)."""
    # T-03400: an input schema we cannot read is treated as unsafe (fail closed: no read-only hint).
    if not isinstance(parameters, dict):
        return True
    props = parameters.get("properties")
    if props is None:
        return False
    if not isinstance(props, (dict, list, tuple)):
        return True
    for name in props:
        n = str(name).casefold()
        if n in GRANT_PARAMS or n in PATH_PARAMS or n.endswith("_path") or n.endswith("_grant_id"):
            return True
    return False


def _effective(a: Optional[Any]) -> Tuple[bool, Optional[bool], Optional[bool], bool]:
    """Annotation as a client sees it, MCP defaults filled in; destructive/idempotent are moot when read-only."""
    if a is None:
        return (False, True, False, True)
    ro = a.readOnlyHint is True
    return (ro,
            None if ro else (True if a.destructiveHint is None else bool(a.destructiveHint)),
            None if ro else bool(a.idempotentHint),
            True if a.openWorldHint is None else bool(a.openWorldHint))


def more_cautious(existing: Optional[Any], derived: Any, allow_read_only: bool) -> Any:
    """Field-by-field merge that never relaxes an annotation (spec §2, TOOLAPI-INV2).

    readOnlyHint is true only if the catalog allows it **and** the existing annotation does not explicitly say
    false (an omitted annotation has no opinion). Destructive and open-world stay true if either side says so
    (omitted counts as true, MCP's default); idempotent is only claimed if both sides claim it. Annotations
    equivalent under MCP semantics are returned unchanged (same object).
    """
    from mcp.types import ToolAnnotations
    old = _effective(existing)
    new = _effective(derived)
    explicit_false = existing is not None and existing.readOnlyHint is False
    # T-03399 F2: an annotation that leaves readOnlyHint unset but claims destructive / non-idempotent behaviour
    # has an opinion: it must not be turned into a read-only one.
    claims_effects = existing is not None and existing.readOnlyHint is None and (
        existing.destructiveHint is True or existing.idempotentHint is False)
    ro = bool(allow_read_only and new[0] and not explicit_false and not claims_effects and
              (existing is None or old[0] or existing.readOnlyHint is None))
    if ro:
        merged = (True, None, None, old[3] or new[3])
    else:
        merged = (False, (old[1] is not False) or (new[1] is not False), bool(old[2]) and bool(new[2]),
                  old[3] or new[3])
    if existing is not None and merged == old:
        return existing                     # equivalent: keep the module's own annotation untouched
    title = (existing.title if existing is not None and existing.title else None) or getattr(derived, "title", None)
    return ToolAnnotations(title=title, readOnlyHint=merged[0], destructiveHint=merged[1],
                           idempotentHint=merged[2], openWorldHint=merged[3])


def apply_catalog_annotations(mcp_app: Any) -> Dict[str, Any]:
    """Applies catalog-derived annotations to every served tool; returns counts (spec §2).

    A broken catalog changes nothing (the server still starts; T-03370 pattern).
    """
    try:
        catalog = default_catalog()
    except ToolRegistryError:
        print(f"aiosh-mcp: {TOOLREG_ERR_UNAVAILABLE}: tool annotations left unchanged", file=sys.stderr)
        return {"error": TOOLREG_ERR_UNAVAILABLE}
    counts = {"applied": 0, "unchanged": 0, "skipped_unregistered": 0, "errors": 0}
    for tool in mcp_app._tool_manager.list_tools():
        try:
            entry = catalog.resolve(tool.name)
            if entry is None:
                counts["skipped_unregistered"] += 1
                continue
            allow = (entry.effect is Effect.READ_ONLY and not entry.requires_grant
                     and entry.category.value in READ_ONLY_HINT_CATEGORIES
                     and entry.scope_kind is ScopeKind.NONE                      # T-03399 F4
                     and not unsafe_for_read_only_hint(tool.parameters))        # T-03399 F1, F4
            merged = more_cautious(tool.annotations, catalog.annotations(tool.name), allow)
        except Exception as exc:  # T-03400: one odd tool must not abort server import; leave it as it was
            counts["errors"] += 1
            print(f"aiosh-mcp: tool annotations unchanged for {str(tool.name)[:64]!r} ({type(exc).__name__})",
                  file=sys.stderr)
            continue
        if merged is tool.annotations:
            counts["unchanged"] += 1
        else:
            tool.annotations = merged
            counts["applied"] += 1
    return counts


def _unavailable(exc: Exception) -> Dict[str, Any]:
    return {"ok": False, "error_code": TOOLREG_ERR_UNAVAILABLE,
            "error": f"{TOOLREG_ERR_UNAVAILABLE}: tool registry unavailable ({type(exc).__name__})"}


def register_tool_registry_api_tools(mcp_app: Any) -> None:
    """Registers ``aios_tool_registry_decide`` and ``aios_tool_registry_stats`` (spec §1). Read-only, no token."""
    from mcp.types import ToolAnnotations

    from aiosh_mcp import tool_registry_service as trs

    decide_service: Dict[str, Any] = {}

    def own_service() -> Any:
        # T-03399 F3: decide() gets its own counters (same catalog and mode as the server), so a caller cannot
        # inflate the dispatch disagreement counts or fill the unregistered samples, nor probe them (S1).
        if "svc" not in decide_service:
            decide_service["svc"] = trs.ToolRegistryService(mode=trs.service().mode)
        return decide_service["svc"]

    def ann(name: str) -> Any:
        try:
            return default_catalog().annotations(name)
        except ToolRegistryError:
            return ToolAnnotations(readOnlyHint=True, openWorldHint=False)

    @mcp_app.tool(name=DECIDE_TOOL, annotations=ann(DECIDE_TOOL))
    def aios_tool_registry_decide(name: NameArg, require_grant: bool = False) -> dict:
        """The tool registry service's decision for a call to ``name`` on this server: canonical name,
        registered, requires_grant, irreversible, scope kinds, disagreements with the legacy rules.
        Decisions are per tool name (target_checked=false). Read-only, no token."""
        try:
            d = own_service().decide(name, require_grant=bool(require_grant))
        except Exception as exc:  # broken catalog or service: explicit, never a crash
            return _unavailable(exc)
        return {"ok": True, "data": {"canonical": d.canonical, "registered": d.registered,
                                     "requires_grant": d.requires_grant, "irreversible": d.irreversible,
                                     "scope_kinds": [k.value for k in d.scope_kinds],
                                     "disagreements": list(d.disagreements), "mode": d.mode,
                                     "target_checked": False}}

    @mcp_app.tool(name=STATS_TOOL, annotations=ann(STATS_TOOL))
    def aios_tool_registry_stats() -> dict:
        """This server's tool registry counters: mode, decisions, disagreements by kind, unregistered
        decisions (with keyed hashes, never names), and how many disagreement lines were logged or
        suppressed. Read-only, no token."""
        try:
            return {"ok": True, "data": {"service": trs.service().stats(), "reports": trs.report_stats()}}
        except Exception as exc:
            return _unavailable(exc)
