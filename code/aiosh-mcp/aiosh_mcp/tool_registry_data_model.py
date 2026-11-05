"""Tool Registry & Taxonomy data model (T-03365 scaffold).

Spec: docs/tasks/evidence/T-03364-spec.md. One trusted, server-side description per tool:
its canonical (grant/audit) name, its MCP aliases, and its taxonomy (category, effect,
irreversibility, scope kind). MCP ``ToolAnnotations`` are *derived* from an entry, never read
(MCP 2025-06-18: annotations are untrusted hints). TOOLREG-INV1..TOOLREG-INV6.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Tuple

TOOLREG_ERR_INVALID_NAME = "TOOLREG_ERR_INVALID_NAME"
TOOLREG_ERR_INCONSISTENT = "TOOLREG_ERR_INCONSISTENT"
TOOLREG_ERR_DUPLICATE = "TOOLREG_ERR_DUPLICATE"
TOOLREG_ERR_BOUNDS = "TOOLREG_ERR_BOUNDS"
TOOLREG_ERR_UNKNOWN = "TOOLREG_ERR_UNKNOWN"

SCHEMA_VERSION = 1
MAX_NAME_LEN = 64            # = mcp_server_core_data_model.MAX_TOOL_NAME_LEN
MAX_TITLE_LEN = 64
MAX_MCP_NAMES = 8
MAX_CATALOG_ENTRIES = 512
#: Lower-case dotted canonical names (spec §2.2): case variants cannot alias one another.
CANONICAL_RE = re.compile(r"^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*$")
#: MCP-surface names: the existing MCPDM identifier rule.
MCP_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
#: Prefixes whose targets are network addresses (same rule as audit_client.grant_check).
NETWORK_PREFIXES = ("pentest.", "network.")


class Category(str, enum.Enum):
    FS_READ = "fs.read"
    FS_WRITE = "fs.write"
    PROCESS = "process"
    AUDIT = "audit"
    PENTEST = "pentest"
    NETWORK = "network"
    GUI = "gui"
    SYSTEM = "system"
    AGENT_LOOP = "agent_loop"
    MODEL_BACKEND = "model_backend"
    MCP_CORE = "mcp_core"
    SERVICE = "service"
    ADMIN = "admin"


class Effect(str, enum.Enum):
    READ_ONLY = "read_only"
    ADDITIVE = "additive"
    DESTRUCTIVE = "destructive"


class ScopeKind(str, enum.Enum):
    NONE = "none"
    PATH = "path"
    NETWORK = "network"


class ToolRegistryError(ValueError):
    """Invalid entry/catalog or unknown tool; ``code`` is a ``TOOLREG_ERR_*`` value."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True)
class ToolEntry:
    """One registered tool (spec §2.2). Validated on construction (TOOLREG-INV1)."""

    canonical: str
    mcp_names: Tuple[str, ...]
    title: str
    category: Category
    effect: Effect
    irreversible: bool
    scope_kind: ScopeKind
    open_world: bool
    requires_grant: bool
    idempotent: bool = False

    def validate(self) -> None:
        raise NotImplementedError("T-03366: ToolEntry.validate")

    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError("T-03366: ToolEntry.to_dict")


class ToolCatalog:
    """Immutable set of entries with case-insensitive unique names (spec §2.4, TOOLREG-INV2/INV5)."""

    def __init__(self, entries: Iterable[ToolEntry]) -> None:
        raise NotImplementedError("T-03366: ToolCatalog")

    def get(self, canonical: str) -> Optional[ToolEntry]:
        raise NotImplementedError("T-03366: ToolCatalog.get")

    def resolve(self, name: str) -> Optional[ToolEntry]:
        raise NotImplementedError("T-03366: ToolCatalog.resolve")

    def profile(self, name: str) -> ToolEntry:
        raise NotImplementedError("T-03366: ToolCatalog.profile")

    def require(self, name: str) -> ToolEntry:
        raise NotImplementedError("T-03366: ToolCatalog.require")

    def entries(self) -> Tuple[ToolEntry, ...]:
        raise NotImplementedError("T-03366: ToolCatalog.entries")

    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError("T-03366: ToolCatalog.to_dict")

    def export_json(self) -> str:
        raise NotImplementedError("T-03366: ToolCatalog.export_json")

    def annotations(self, name: str) -> Any:
        raise NotImplementedError("T-03366: ToolCatalog.annotations")


def unknown_profile(name: str) -> ToolEntry:
    """Fail-closed profile for an unregistered name (spec §2.5, TOOLREG-INV3)."""
    raise NotImplementedError("T-03366: unknown_profile")


def default_catalog() -> ToolCatalog:
    """The built-in catalog (spec §3)."""
    raise NotImplementedError("T-03366: default_catalog")
