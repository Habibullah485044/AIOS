"""Tool Registry & Taxonomy MCP API surface (T-03395 scaffold).

Spec: docs/tasks/evidence/T-03394-spec.md. Two more read-only tools (``aios_tool_registry_decide``,
``aios_tool_registry_stats``) and ``apply_catalog_annotations``, which sets every served tool's MCP
annotations from the catalog without ever making a tool look *less* careful (TOOLAPI-INV1..TOOLAPI-INV4).
"""

from __future__ import annotations

from typing import Any, Dict, Optional

DECIDE_TOOL = "aios_tool_registry_decide"
STATS_TOOL = "aios_tool_registry_stats"
#: Categories in which a read-only, grant-free entry may be advertised as readOnlyHint=true (spec §2).
READ_ONLY_HINT_CATEGORIES = ("audit", "agent_loop", "mcp_core", "model_backend", "fs.read", "service")


def more_cautious(existing: Optional[Any], derived: Any, allow_read_only: bool) -> Any:
    """Field-by-field merge that never relaxes an annotation (spec §2, TOOLAPI-INV2)."""
    raise NotImplementedError("T-03396: more_cautious")


def apply_catalog_annotations(mcp_app: Any) -> Dict[str, Any]:
    """Applies catalog-derived annotations to every served tool; returns counts (spec §2)."""
    raise NotImplementedError("T-03396: apply_catalog_annotations")


def register_tool_registry_api_tools(mcp_app: Any) -> None:
    """Registers ``aios_tool_registry_decide`` and ``aios_tool_registry_stats`` (spec §1)."""
    raise NotImplementedError("T-03396: register_tool_registry_api_tools")
