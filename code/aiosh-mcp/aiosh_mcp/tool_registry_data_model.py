"""Tool Registry & Taxonomy data model (T-03365 scaffold / T-03366 impl).

Spec: docs/tasks/evidence/T-03364-spec.md. One trusted, server-side description per tool:
its canonical (grant/audit) name, its MCP aliases, and its taxonomy (category, effect,
irreversibility, scope kind). MCP ``ToolAnnotations`` are *derived* from an entry, never read
(MCP 2025-06-18: annotations are untrusted hints). TOOLREG-INV1..TOOLREG-INV6.
"""

from __future__ import annotations

import enum
import functools
import hashlib
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
#: The catalog failed to build; the registry MCP tools answer with this instead of taking the server down.
TOOLREG_ERR_UNAVAILABLE = "TOOLREG_ERR_UNAVAILABLE"

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
_FORBIDDEN_TEXT = re.compile(
    "[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]")   # C0/C1, line/para separators, bidi marks and overrides (T-03389 #5)
#: Categories whose tools are always irreversible (spec §2.3 rule 5).
_IRREVERSIBLE_CATEGORIES = ("fs.write", "system")
#: Names the *existing* enforcement rules treat as irreversible: the union of audit_client.grant_check and
#: agent_loop_policy.is_irreversible (T-03369 #3). A catalog entry may be stricter, never weaker.
IRREVERSIBLE_NAME_PREFIXES = ("pentest.", "fs.write", "process.", "shell.")
IRREVERSIBLE_NAMES = ("system.reboot", "system.shutdown", "pentest")
#: Bare family names the agent-loop gate also treats as network tools (agent_loop_gate.tool_refusal).
NETWORK_NAMES = ("pentest", "network")
#: Prefix of the synthetic canonical name given to malformed unknown names (one per name, never registrable).
UNREGISTERED_PREFIX = "unregistered."


def irreversible_by_name(name: str) -> bool:
    """True if any existing name rule treats ``name`` as irreversible (case-insensitive)."""
    n = name.casefold()
    return n.startswith(IRREVERSIBLE_NAME_PREFIXES) or n in IRREVERSIBLE_NAMES


def network_by_name(name: str) -> bool:
    """The network-target rule of grant_check / agent_loop_gate, case-insensitive, bare names included."""
    n = name.casefold()
    return n.startswith(NETWORK_PREFIXES) or n in NETWORK_NAMES


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
        # T-03369 #2: pentest tools are irreversible, but offline ones (tshark -r, aircrack-ng) target a *path*.
        if self.category is Category.PENTEST and not (self.irreversible and self.scope_kind is not ScopeKind.NONE):
            _fail(TOOLREG_ERR_INCONSISTENT, f"{self.canonical}: pentest tools are irreversible and path- or "
                                            f"network-scoped")
        if self.category is Category.NETWORK and self.scope_kind is not ScopeKind.NETWORK:
            _fail(TOOLREG_ERR_INCONSISTENT, f"{self.canonical}: network tools are network-scoped")
        # T-03369 #3: never weaker than the name rules enforcement uses today.
        if irreversible_by_name(self.canonical) and not (self.irreversible and self.requires_grant):
            _fail(TOOLREG_ERR_INCONSISTENT, f"{self.canonical}: existing name rules treat it as irreversible; "
                                            f"the entry must be irreversible and require a grant")
        if self.category.value in _IRREVERSIBLE_CATEGORIES and not self.irreversible:
            _fail(TOOLREG_ERR_INCONSISTENT, f"{self.canonical}: {self.category.value} tools are irreversible")

    def to_dict(self) -> Dict[str, Any]:
        return {"canonical": self.canonical, "mcp_names": list(self.mcp_names), "title": self.title,
                "category": self.category.value, "effect": self.effect.value, "irreversible": self.irreversible,
                "scope_kind": self.scope_kind.value, "open_world": self.open_world,
                "requires_grant": self.requires_grant, "idempotent": self.idempotent}


_SEPARATORS = re.compile(r"[._\-]+")


def _fold(name: str) -> str:
    """Collision key: NFKC + casefold, and ``.``/``_``/``-`` treated as one separator (T-03369 #6)."""
    return _SEPARATORS.sub(".", unicodedata.normalize("NFKC", name).casefold())


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
        folded: Dict[str, Tuple[str, ToolEntry, bool]] = {}
        seen: set = set()
        for e in items:
            if id(e) in seen:          # the same entry listed twice (T-03370; e.g. a bad merge of the seed)
                _fail(TOOLREG_ERR_DUPLICATE, f"entry {e.canonical} is listed twice")
            seen.add(id(e))
            if type(e) is not ToolEntry:
                _fail(TOOLREG_ERR_INCONSISTENT, "catalog entries must be ToolEntry")
            if e.canonical.startswith(UNREGISTERED_PREFIX):        # synthetic names of unknown tools (T-03369 #5)
                _fail(TOOLREG_ERR_INVALID_NAME, f"{e.canonical}: reserved for unregistered tools")
            for i, name in enumerate((e.canonical, *e.mcp_names)):
                key = _fold(name)
                prev = folded.get(key)
                # An alias may fold onto its *own* canonical name (aios_fs_read ~ aios.fs.read); any other
                # collision, across entries or between two aliases of one entry, is ambiguous.
                if prev is not None and not (prev[1] is e and (prev[2] or i == 0)):
                    _fail(TOOLREG_ERR_DUPLICATE, f"name {_shown(name)!r} of {e.canonical} collides with "
                                                 f"{_shown(prev[0])!r}")
                if prev is None or i == 0:
                    folded[key] = (name, e, i == 0)
                by_name[name] = e
        object.__setattr__(self, "_entries", tuple(sorted(items, key=lambda e: e.canonical)))
        object.__setattr__(self, "_by_name", MappingProxyType(by_name))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("ToolCatalog is immutable")

    def __len__(self) -> int:
        return len(self._entries)

    def get(self, canonical: str) -> Optional[ToolEntry]:
        e = self._by_name.get(canonical) if type(canonical) is str else None
        return e if e is not None and e.canonical == canonical else None

    def resolve(self, name: str) -> Optional[ToolEntry]:
        return self._by_name.get(name) if type(name) is str else None   # exact str: no __eq__/__hash__ games

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
    text = str.__str__(name) if isinstance(name, str) else ""
    if 1 <= len(text) <= MAX_NAME_LEN and CANONICAL_RE.fullmatch(text) and not text.startswith(UNREGISTERED_PREFIX):
        canonical = text
    else:
        # One distinct synthetic name per malformed input (T-03369 #5): a grant for one cannot cover another,
        # and the raw name is never echoed.
        canonical = UNREGISTERED_PREFIX + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    network = network_by_name(text)      # case-insensitive, bare names included (T-03369 #4)
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


def _pentest(name: str, title: str, effect: Effect, offline: bool = False) -> ToolEntry:
    """Live pentest tools target hosts (network scope); offline ones read a capture file (path scope)."""
    mcp = "aios_pentest_" + name.split(".", 1)[1].replace("-", "_")
    return _e(name, (mcp,), title, Category.PENTEST, effect, irreversible=True,
              scope=ScopeKind.PATH if offline else ScopeKind.NETWORK, open_world=not offline)


_R, _A, _D = Effect.READ_ONLY, Effect.ADDITIVE, Effect.DESTRUCTIVE
_SEED: Tuple[ToolEntry, ...] = (
    # agent_bridge.CANONICAL_TO_MCP (spec §3)
    # requires_grant: server.aios_fs_read calls _recorded_call(require_grant=True) (T-03369 #1)
    _e("aios.fs.read", ("aios_fs_read",), "Read a text file", Category.FS_READ, _R, scope=ScopeKind.PATH,
       grant=True),
    _e("aios.process.list", ("aios_process_list",), "List processes", Category.PROCESS, _R),
    _e("aios.audit.tail", ("aios_audit_tail",), "Tail the audit ring", Category.AUDIT, _R),
    _e("aios.audit.verify", ("aios_audit_verify",), "Verify the audit chain", Category.AUDIT, _R),
    _pentest("pentest.nmap", "Network scan (nmap)", _A),
    _pentest("pentest.nikto", "Web server scan (nikto)", _A),
    _pentest("pentest.sqlmap", "SQL injection test (sqlmap)", _D),
    # offline: `tshark -r <pcap>` and `aircrack-ng <capture>` read a file (target=path in pentest.py) (T-03369 #2)
    _pentest("pentest.tshark", "Read a packet capture (tshark)", _A, offline=True),
    _pentest("pentest.aircrack-ng", "Wi-Fi key test on a capture", _A, offline=True),
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
    # ---- T-03380: every served MCP tool and every literal audit name ------------------------------------------
    # Multi-action tools (task, compliance, runbook, scan) are classified by their most consequential action
    # for `effect`; `requires_grant` is the action-independent minimum (their own gates require grants per action).
    # release / backup: _dispatch(require_grant=True) (server.py:225,259)
    _e("aios.release.generate", ("aios_release_generate",), "Package a release ISO", Category.SERVICE, _A, grant=True),
    _e("aios.backup.create", ("aios_backup_create",), "Create a system backup zip", Category.SERVICE, _A,
       scope=ScopeKind.PATH, grant=True),
    # agent loop: read surfaces and the legacy data-model init (token-gated)
    _e("aios.agent_loop.config", ("aios_agent_loop_config",), "Agent-loop configuration", Category.AGENT_LOOP, _R),
    _e("aios.agent_loop.doc", ("aios_agent_loop_doc",), "Agent-loop reference", Category.AGENT_LOOP, _R),
    _e("aios.agent_loop.history", ("aios_agent_loop_history",), "Agent-loop audit history", Category.AGENT_LOOP, _R),
    _e("aios.agent_loop.list", ("aios_agent_loop_list",), "List agent loops", Category.AGENT_LOOP, _R),
    _e("aios.agent_loop.metrics", ("aios_agent_loop_metrics",), "Agent-loop metrics", Category.AGENT_LOOP, _R),
    _e("aios.agent_loop.snapshot", ("aios_agent_loop_snapshot",), "Agent-loop snapshot", Category.AGENT_LOOP, _R),
    _e("aios.agent_loop.status", ("aios_agent_loop_status",), "Agent-loop status", Category.AGENT_LOOP, _R),
    _e("aios.agent_loop.validate", ("aios_agent_loop_validate",), "Validate agent-loop runs", Category.AGENT_LOOP, _R),
    _e("aios.agent_loop.init", ("aios_agent_loop_init",), "Initialise an agent loop", Category.AGENT_LOOP, _A,
       grant=True),
    # audit chain, anchors and Proof-of-Restraint
    _e("aios.anchor.create", ("aios_anchor_create",), "Create a signed chain anchor", Category.AUDIT, _A, grant=True),
    _e("aios.anchor.verify", ("aios_anchor_verify",), "Verify chain anchors", Category.AUDIT, _R),
    _e("aios.audit.seen", ("aios_audit_seen",), "Audit membership query", Category.AUDIT, _R),
    _e("aios.audit.segments", ("aios_audit_segments",), "List audit segments", Category.AUDIT, _R),
    _e("aios.restraint.prove", ("aios_restraint_prove",), "Prove a grant was not used", Category.AUDIT, _R),
    _e("aios.restraint.verify", ("aios_restraint_verify",), "Verify a restraint proof", Category.AUDIT, _R),
    _e("pep.capability.redeem", (), "Redeem a PEP capability", Category.ADMIN, _A, grant=True),
    # services with per-action grants
    _e("aios.task", ("aios_task",), "Task ledger control", Category.SERVICE, _A),
    _e("aios.compliance", ("aios_compliance",), "Compliance mapping control", Category.SERVICE, _A),
    _e("aios.runbook", ("aios_runbook",), "Incident runbook control", Category.SERVICE, _D),
    _e("aios.scan", ("aios_scan",), "Security scanning (net, files, web)", Category.NETWORK, _A,
       scope=ScopeKind.NETWORK, open_world=True),
    # MCP server core
    _e("aios.mcp.api.jsonrpc", ("aios_mcp_api_jsonrpc",), "Route a raw JSON-RPC request", Category.MCP_CORE, _A),
    _e("aios.mcp.api.ping", ("aios_mcp_api_ping",), "Ping the MCP core API", Category.MCP_CORE, _R),
    _e("aios.mcp.config.get", ("aios_mcp_config_get",), "MCP core configuration", Category.MCP_CORE, _R),
    _e("aios.mcp.config.validate", ("aios_mcp_config_validate",), "Validate MCP core config", Category.MCP_CORE, _R),
    _e("aios.mcp.core.dispatch", ("aios_mcp_core_dispatch",), "Dispatch via MCP core service", Category.MCP_CORE, _A,
       grant=True),
    _e("aios.mcp.core.list_tools", ("aios_mcp_core_list_tools",), "List MCP core tools", Category.MCP_CORE, _R),
    _e("aios.mcp.core.status", ("aios_mcp_core_status",), "MCP core status", Category.MCP_CORE, _R),
    _e("aios.mcp.doc.lookup", ("aios_mcp_doc_lookup",), "MCP core documentation", Category.MCP_CORE, _R),
    _e("aios.mcp.observability.snapshot", ("aios_mcp_observability_snapshot",), "MCP core metrics",
       Category.MCP_CORE, _R),
    _e("aios.mcp.policy.evaluate", ("aios_mcp_policy_evaluate",), "Evaluate MCP core policy", Category.MCP_CORE, _R),
    _e("aios.mcp.policy.status", ("aios_mcp_policy_status",), "MCP core policy status", Category.MCP_CORE, _R),
    _e("aios.mcp.recovery.check", ("aios_mcp_recovery_check",), "Check an MCP state store", Category.MCP_CORE, _R,
       scope=ScopeKind.PATH),
    _e("aios.mcp.recovery.repair", ("aios_mcp_recovery_repair",), "Repair an MCP state store", Category.MCP_CORE, _D,
       scope=ScopeKind.PATH, grant=True),
    _e("aios.mcp.test.run", ("aios_mcp_test_run",), "Run MCP core self-tests", Category.MCP_CORE, _R),
    # model backends (completions call external model APIs: open world)
    _e("aios.model.complete", ("aios_model_complete",), "Model completion", Category.MODEL_BACKEND, _A,
       open_world=True, grant=True),
    _e("aios.model.doc.get", ("aios_model_doc_get",), "Model backend doc topic", Category.MODEL_BACKEND, _R),
    _e("aios.model.doc.list", ("aios_model_doc_list",), "List model backend docs", Category.MODEL_BACKEND, _R),
    _e("aios.model.doc.search", ("aios_model_doc_search",), "Search model backend docs", Category.MODEL_BACKEND, _R),
    _e("aios.model.endpoint.list", ("aios_model_endpoint_list",), "List model endpoints", Category.MODEL_BACKEND, _R),
    _e("aios.model.endpoint.register", ("aios_model_endpoint_register",), "Register a model endpoint",
       Category.MODEL_BACKEND, _A, grant=True, idempotent=True),
    _e("aios.model.observability.snapshot", ("aios_model_observability_snapshot",), "Model backend metrics",
       Category.MODEL_BACKEND, _R),
    _e("aios.model.recover_config", ("aios_model_recover_config",), "Recover model config", Category.MODEL_BACKEND,
       _D, scope=ScopeKind.PATH, grant=True),
    _e("aios.model.service.health", ("aios_model_service_health",), "Model service health", Category.MODEL_BACKEND,
       _R, open_world=True),
    _e("aios.model.validate_config", ("aios_model_validate_config",), "Validate model config",
       Category.MODEL_BACKEND, _R, scope=ScopeKind.PATH),
    _e("model_backend.complete", ("model_backend_complete",), "Model inference with fallback",
       Category.MODEL_BACKEND, _A, open_world=True, grant=True),
    _e("model_backend.health", ("model_backend_health",), "Model backend health", Category.MODEL_BACKEND, _R,
       open_world=True),
    _e("model_backend.list", ("model_backend_list",), "List model backends", Category.MODEL_BACKEND, _R),
    _e("model_backend.register", ("model_backend_register",), "Register a model backend", Category.MODEL_BACKEND, _A,
       grant=True),
    _e("model_backend.show", ("model_backend_show",), "Show a model backend", Category.MODEL_BACKEND, _R),
    # the irreversible names audit_client.grant_check knows
    # the registry's own read-only MCP tools (T-03368)
    _e("aios.tool_registry.list", ("aios_tool_registry_list",), "List the tool catalog", Category.MCP_CORE, _R),
    _e("aios.tool_registry.get", ("aios_tool_registry_get",), "Look up a tool's taxonomy", Category.MCP_CORE, _R),
    _e("aios.tool_registry.decide", ("aios_tool_registry_decide",), "Registry decision for a tool", Category.MCP_CORE,
       _R),
    _e("aios.tool_registry.stats", ("aios_tool_registry_stats",), "Registry counters", Category.MCP_CORE, _R),
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


def _unavailable(reason: str) -> Dict[str, Any]:
    return {"ok": False, "error_code": TOOLREG_ERR_UNAVAILABLE,
            "error": f"{TOOLREG_ERR_UNAVAILABLE}: tool catalog unavailable ({reason})"}


def register_tool_registry_tools(mcp_app: Any) -> None:
    """Registers the read-only catalog tools on ``mcp_app`` (TOOLREG-INV5: no tool can change the catalog).

    T-03370: a catalog that fails to build (a bad seed edit) must not take the other ~67 server tools down at
    import. The two tools are still registered and answer every call with ``TOOLREG_ERR_UNAVAILABLE``; the
    failure is reported on stderr. CI still fails on it (the registry tests build the catalog directly).
    """
    import sys
    from mcp.types import ToolAnnotations

    try:
        catalog: Optional[ToolCatalog] = default_catalog()
        broken: Optional[str] = None
    except ToolRegistryError as exc:
        catalog, broken = None, exc.code
        print(f"aiosh-mcp: {TOOLREG_ERR_UNAVAILABLE}: {_shown(exc)}", file=sys.stderr)

    def ann(name: str) -> Any:
        if catalog is not None:
            return catalog.annotations(name)
        return ToolAnnotations(readOnlyHint=True, openWorldHint=False)     # what the entries say when intact

    @mcp_app.tool(name=LIST_TOOL, annotations=ann(LIST_TOOL))
    def aios_tool_registry_list(category: CategoryArg = None) -> dict:
        """Lists the trusted tool catalog (canonical name, MCP aliases, category, effect, irreversible,
        scope kind). Read-only, no token. Optionally filtered by category."""
        if catalog is None:
            return _unavailable(str(broken))
        entries = [e.to_dict() for e in catalog.entries() if category is None or e.category.value == category]
        return {"ok": True, "data": {"schema_version": SCHEMA_VERSION, "count": len(entries), "entries": entries}}

    @mcp_app.tool(name=GET_TOOL, annotations=ann(GET_TOOL))
    def aios_tool_registry_get(name: NameArg) -> dict:
        """Resolves a canonical or MCP tool name to its taxonomy. An unregistered name returns the
        fail-closed profile (irreversible, grant required) with registered=false. Read-only, no token."""
        if catalog is None:
            # Still fail closed: callers get the unknown profile shape plus an explicit error.
            return {**_unavailable(str(broken)), "data": {"registered": False, "entry": unknown_profile(name).to_dict()}}
        entry = catalog.resolve(name)
        profile = entry or unknown_profile(name)
        return {"ok": True, "data": {"registered": entry is not None, "entry": profile.to_dict()}}
