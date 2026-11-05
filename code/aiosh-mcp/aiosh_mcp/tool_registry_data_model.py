"""Tool Registry & Taxonomy data model (T-03365 scaffold / T-03366 impl).

Spec: docs/tasks/evidence/T-03364-spec.md. One trusted, server-side description per tool:
its canonical (grant/audit) name, its MCP aliases, and its taxonomy (category, effect,
irreversibility, scope kind). MCP ``ToolAnnotations`` are *derived* from an entry, never read
(MCP 2025-06-18: annotations are untrusted hints). TOOLREG-INV1..TOOLREG-INV6.
"""

from __future__ import annotations

import enum
import functools
import json
import re
import unicodedata
from dataclasses import dataclass
from types import MappingProxyType
from typing import Annotated, Any, Dict, Iterable, Literal, Mapping, Optional, Tuple

from pydantic import Field

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
#: Control characters and bidi overrides (MCPDM-INV3) are never allowed in a title or shown in errors.
_FORBIDDEN_TEXT = re.compile("[\x00-\x1f\x7f‪-‮⁦-⁩]")
#: Categories whose tools are always irreversible (spec §2.3 rule 5).
_IRREVERSIBLE_CATEGORIES = ("fs.write", "system")


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


def _shown(value: Any) -> str:
    """A name as it may appear in an error: control/bidi characters removed, at most 80 characters."""
    return _FORBIDDEN_TEXT.sub("", str(value))[:80]


def _fail(code: str, message: str) -> None:
    raise ToolRegistryError(code, message)


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

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        # Names and bounds (spec §2.2, §2.7).
        if not isinstance(self.canonical, str) or not (1 <= len(self.canonical) <= MAX_NAME_LEN) \
                or not CANONICAL_RE.fullmatch(self.canonical):
            _fail(TOOLREG_ERR_INVALID_NAME, f"canonical name {_shown(self.canonical)!r} must match "
                                            f"{CANONICAL_RE.pattern} and be 1..{MAX_NAME_LEN} chars")
        if not isinstance(self.mcp_names, tuple):
            _fail(TOOLREG_ERR_INCONSISTENT, f"{self.canonical}: mcp_names must be a tuple")
        if len(self.mcp_names) > MAX_MCP_NAMES:
            _fail(TOOLREG_ERR_BOUNDS, f"{self.canonical}: at most {MAX_MCP_NAMES} MCP names")
        for name in self.mcp_names:
            if not isinstance(name, str) or not (1 <= len(name) <= MAX_NAME_LEN) or not MCP_NAME_RE.fullmatch(name):
                _fail(TOOLREG_ERR_INVALID_NAME, f"{self.canonical}: MCP name {_shown(name)!r} is invalid")
        if not isinstance(self.title, str) or not (1 <= len(self.title) <= MAX_TITLE_LEN):
            _fail(TOOLREG_ERR_BOUNDS, f"{self.canonical}: title must be 1..{MAX_TITLE_LEN} chars")
        if _FORBIDDEN_TEXT.search(self.title) or not self.title.isprintable():
            _fail(TOOLREG_ERR_INVALID_NAME, f"{self.canonical}: title contains control or bidi characters")
        # Types: enums are enums and flags are real bools (a 1 or "yes" would hide a mistake).
        for attr, kind in (("category", Category), ("effect", Effect), ("scope_kind", ScopeKind)):
            if type(getattr(self, attr)) is not kind:
                _fail(TOOLREG_ERR_INCONSISTENT, f"{self.canonical}: {attr} must be a {kind.__name__}")
        for attr in ("irreversible", "open_world", "requires_grant", "idempotent"):
            if type(getattr(self, attr)) is not bool:
                _fail(TOOLREG_ERR_INCONSISTENT, f"{self.canonical}: {attr} must be a bool")
        # Consistency rules (spec §2.3).
        read_only = self.effect is Effect.READ_ONLY
        if read_only and (self.irreversible or self.idempotent):
            _fail(TOOLREG_ERR_INCONSISTENT, f"{self.canonical}: a read_only tool cannot be irreversible or idempotent")
        if self.irreversible and not self.requires_grant:
            _fail(TOOLREG_ERR_INCONSISTENT, f"{self.canonical}: an irreversible tool must require a grant")
        if self.scope_kind is ScopeKind.NETWORK and not self.open_world:
            _fail(TOOLREG_ERR_INCONSISTENT, f"{self.canonical}: a network-scoped tool is open-world")
        if self.category is Category.PENTEST and not (self.scope_kind is ScopeKind.NETWORK and self.irreversible):
            _fail(TOOLREG_ERR_INCONSISTENT, f"{self.canonical}: pentest tools are network-scoped and irreversible")
        if self.category.value in _IRREVERSIBLE_CATEGORIES and not self.irreversible:
            _fail(TOOLREG_ERR_INCONSISTENT, f"{self.canonical}: {self.category.value} tools are irreversible")

    def to_dict(self) -> Dict[str, Any]:
        return {"canonical": self.canonical, "mcp_names": list(self.mcp_names), "title": self.title,
                "category": self.category.value, "effect": self.effect.value, "irreversible": self.irreversible,
                "scope_kind": self.scope_kind.value, "open_world": self.open_world,
                "requires_grant": self.requires_grant, "idempotent": self.idempotent}


def _fold(name: str) -> str:
    return unicodedata.normalize("NFKC", name).casefold()


class ToolCatalog:
    """Immutable set of entries with case-insensitive unique names (spec §2.4, TOOLREG-INV2/INV5).

    There is deliberately no method that adds, removes or changes an entry: the catalog is code.
    """

    __slots__ = ("_entries", "_by_name")

    def __init__(self, entries: Iterable[ToolEntry]) -> None:
        items = tuple(entries)
        if len(items) > MAX_CATALOG_ENTRIES:
            _fail(TOOLREG_ERR_BOUNDS, f"catalog has {len(items)} entries; at most {MAX_CATALOG_ENTRIES}")
        by_name: Dict[str, ToolEntry] = {}
        folded: Dict[str, str] = {}
        for e in items:
            if not isinstance(e, ToolEntry):
                _fail(TOOLREG_ERR_INCONSISTENT, "catalog entries must be ToolEntry")
            for name in (e.canonical, *e.mcp_names):
                key = _fold(name)
                if key in folded:
                    _fail(TOOLREG_ERR_DUPLICATE, f"name {_shown(name)!r} of {e.canonical} collides with "
                                                 f"{_shown(folded[key])!r}")
                folded[key] = name
                by_name[name] = e
        object.__setattr__(self, "_entries", tuple(sorted(items, key=lambda e: e.canonical)))
        object.__setattr__(self, "_by_name", MappingProxyType(by_name))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("ToolCatalog is immutable")

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, canonical: str) -> Optional[ToolEntry]:
        e = self._by_name.get(canonical) if isinstance(canonical, str) else None
        return e if e is not None and e.canonical == canonical else None

    def resolve(self, name: str) -> Optional[ToolEntry]:
        return self._by_name.get(name) if isinstance(name, str) else None

    def profile(self, name: str) -> ToolEntry:
        return self.resolve(name) or unknown_profile(name)

    def require(self, name: str) -> ToolEntry:
        e = self.resolve(name)
        if e is None:
            _fail(TOOLREG_ERR_UNKNOWN, f"tool {_shown(name)!r} is not registered")
        return e

    def entries(self) -> Tuple[ToolEntry, ...]:
        return self._entries

    def names(self) -> Mapping[str, ToolEntry]:
        """Read-only mapping of every canonical and MCP name to its entry."""
        return self._by_name

    def to_dict(self) -> Dict[str, Any]:
        return {"schema_version": SCHEMA_VERSION, "entries": [e.to_dict() for e in self._entries]}

    def export_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    def annotations(self, name: str) -> Any:
        """MCP ``ToolAnnotations`` derived from the entry (spec §2.6); never read from anywhere (TOOLREG-INV4)."""
        from mcp.types import ToolAnnotations
        e = self.require(name)
        read_only = e.effect is Effect.READ_ONLY
        return ToolAnnotations(title=e.title, readOnlyHint=read_only,
                               destructiveHint=None if read_only else e.effect is Effect.DESTRUCTIVE,
                               idempotentHint=None if read_only else e.idempotent,
                               openWorldHint=e.open_world)


def unknown_profile(name: str) -> ToolEntry:
    """Fail-closed profile for an unregistered name (spec §2.5, TOOLREG-INV3). Never registered."""
    text = name if isinstance(name, str) else ""
    canonical = text if 1 <= len(text) <= MAX_NAME_LEN and CANONICAL_RE.fullmatch(text) else "unregistered"
    network = text.startswith(NETWORK_PREFIXES)
    return ToolEntry(canonical=canonical, mcp_names=(), title="unregistered tool", category=Category.ADMIN,
                     effect=Effect.DESTRUCTIVE, irreversible=True,
                     scope_kind=ScopeKind.NETWORK if network else ScopeKind.PATH, open_world=True,
                     requires_grant=True, idempotent=False)


def _e(canonical: str, mcp: Tuple[str, ...], title: str, category: Category, effect: Effect, *,
       irreversible: bool = False, scope: ScopeKind = ScopeKind.NONE, open_world: bool = False,
       grant: Optional[bool] = None, idempotent: bool = False) -> ToolEntry:
    return ToolEntry(canonical=canonical, mcp_names=mcp, title=title, category=category, effect=effect,
                     irreversible=irreversible, scope_kind=scope, open_world=open_world,
                     requires_grant=irreversible if grant is None else grant, idempotent=idempotent)


def _pentest(name: str, title: str, effect: Effect) -> ToolEntry:
    mcp = "aios_pentest_" + name.split(".", 1)[1].replace("-", "_")
    return _e(name, (mcp,), title, Category.PENTEST, effect, irreversible=True, scope=ScopeKind.NETWORK,
              open_world=True)


_R, _A, _D = Effect.READ_ONLY, Effect.ADDITIVE, Effect.DESTRUCTIVE
_SEED: Tuple[ToolEntry, ...] = (
    # agent_bridge.CANONICAL_TO_MCP (spec §3)
    _e("aios.fs.read", ("aios_fs_read",), "Read a text file", Category.FS_READ, _R, scope=ScopeKind.PATH),
    _e("aios.process.list", ("aios_process_list",), "List processes", Category.PROCESS, _R),
    _e("aios.audit.tail", ("aios_audit_tail",), "Tail the audit ring", Category.AUDIT, _R),
    _e("aios.audit.verify", ("aios_audit_verify",), "Verify the audit chain", Category.AUDIT, _R),
    _pentest("pentest.nmap", "Network scan (nmap)", _A),
    _pentest("pentest.nikto", "Web server scan (nikto)", _A),
    _pentest("pentest.sqlmap", "SQL injection test (sqlmap)", _D),
    _pentest("pentest.tshark", "Packet capture (tshark)", _A),
    _pentest("pentest.aircrack-ng", "Wi-Fi key test (aircrack-ng)", _D),
    # agent-loop audit names, aligned with agent_loop_mcp.TOOL_ANNOTATIONS
    _e("aios.agent_loop.start", ("aios_agent_loop_start",), "Start an agent loop", Category.AGENT_LOOP, _A,
       grant=True),
    _e("aios.agent_loop.step", ("aios_agent_loop_advance",), "Advance an agent loop", Category.AGENT_LOOP, _A,
       grant=True),
    _e("aios.agent_loop.abort", ("aios_agent_loop_abort",), "Abort an agent loop", Category.AGENT_LOOP, _D,
       grant=True, idempotent=True),
    _e("aios.agent_loop.complete", ("aios_agent_loop_complete",), "Complete an agent loop", Category.AGENT_LOOP, _D,
       grant=True),
    _e("aios.agent_loop.recover", ("aios_agent_loop_recover",), "Recover orphaned loop runs", Category.AGENT_LOOP,
       _A, grant=True),
    # archival rotation: never destroys rows, needs a grant (server.aios_audit_rotate)
    _e("audit.rotate", ("aios_audit_rotate",), "Rotate the audit ring", Category.AUDIT, _A, grant=True),
    # the irreversible names audit_client.grant_check knows
    # the registry's own read-only MCP tools (T-03368)
    _e("aios.tool_registry.list", ("aios_tool_registry_list",), "List the tool catalog", Category.MCP_CORE, _R),
    _e("aios.tool_registry.get", ("aios_tool_registry_get",), "Look up a tool's taxonomy", Category.MCP_CORE, _R),
    _e("fs.write", (), "Write a file", Category.FS_WRITE, _D, irreversible=True, scope=ScopeKind.PATH),
    _e("system.reboot", (), "Reboot the system", Category.SYSTEM, _D, irreversible=True),
    _e("system.shutdown", (), "Shut the system down", Category.SYSTEM, _D, irreversible=True),
)


@functools.lru_cache(maxsize=1)
def default_catalog() -> ToolCatalog:
    """The built-in catalog (spec §3). Built once; immutable."""
    return ToolCatalog(_SEED)


# ---- MCP surface (T-03368) ------------------------------------------------------------------------------------
#: The registry's own read-only tools are catalog entries too, so their annotations are derived like any other.
LIST_TOOL = "aios_tool_registry_list"
GET_TOOL = "aios_tool_registry_get"
MAX_QUERY_LEN = 256
# Module-level argument types: tool signatures are evaluated in module globals (PEP 563 strings).
CategoryArg = Optional[Literal[tuple(c.value for c in Category)]]  # type: ignore[valid-type]
NameArg = Annotated[str, Field(min_length=1, max_length=MAX_QUERY_LEN)]


def register_tool_registry_tools(mcp_app: Any) -> None:
    """Registers the read-only catalog tools on ``mcp_app`` (TOOLREG-INV5: no tool can change the catalog)."""
    catalog = default_catalog()

    @mcp_app.tool(name=LIST_TOOL, annotations=catalog.annotations(LIST_TOOL))
    def aios_tool_registry_list(category: CategoryArg = None) -> dict:
        """Lists the trusted tool catalog (canonical name, MCP aliases, category, effect, irreversible,
        scope kind). Read-only, no token. Optionally filtered by category."""
        entries = [e.to_dict() for e in catalog.entries() if category is None or e.category.value == category]
        return {"ok": True, "data": {"schema_version": SCHEMA_VERSION, "count": len(entries), "entries": entries}}

    @mcp_app.tool(name=GET_TOOL, annotations=catalog.annotations(GET_TOOL))
    def aios_tool_registry_get(name: NameArg) -> dict:
        """Resolves a canonical or MCP tool name to its taxonomy. An unregistered name returns the
        fail-closed profile (irreversible, grant required) with registered=false. Read-only, no token."""
        entry = catalog.resolve(name)
        profile = entry or unknown_profile(name)
        return {"ok": True, "data": {"registered": entry is not None, "entry": profile.to_dict()}}
