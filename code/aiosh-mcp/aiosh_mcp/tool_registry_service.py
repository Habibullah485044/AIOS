"""Tool Registry & Taxonomy core service (T-03375 scaffold / T-03376 impl).

Spec: docs/tasks/evidence/T-03374-spec.md. A pure decision service over the immutable catalog: for one tool
call it reports the canonical name, grant requirement, irreversibility and applicable scopes, and where the
catalog disagrees with the legacy name rules. Shadow mode (default) changes no enforcement; strict mode can
only tighten it (TOOLSVC-INV1..TOOLSVC-INV5).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from aiosh_mcp.tool_registry_data_model import (
    NETWORK_PREFIXES,
    ScopeKind,
    ToolCatalog,
    default_catalog,
    irreversible_by_name,
)

TOOLSVC_ERR_MODE = "TOOLSVC_ERR_MODE"
ENV_MODE = "AIOSH_TOOL_REGISTRY_MODE"
MODES = ("shadow", "strict")
DEFAULT_MODE = "shadow"
DISAGREEMENT_KINDS = ("unregistered", "grant", "irreversible", "scope")
MAX_UNREGISTERED_SAMPLES = 50
#: Structured stderr event name for a disagreement (no audit row: TOOLSVC-INV3).
LOG_EVENT = "tool_registry.disagreement"
MAX_LOGGED_TOOL_LEN = 64
#: report() writes each distinct (surface, tool, disagreements) at most once, and at most this many lines per
#: process: a blocked stderr pipe can never stall tool calls (T-03379 #1).
MAX_REPORT_LINES = 32
#: Per-process key for the unregistered-name samples: not reversible by dictionary, not linkable across
#: processes (T-03379 #6).
_SAMPLE_KEY = secrets.token_bytes(16)


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


# ---- the legacy rules, exactly as enforced today (compared, never replaced, in this epic) -------------------------

def legacy_requires_grant(tool: str) -> bool:
    """``audit_client.grant_check``: irreversible names need a grant (case-sensitive, as there)."""
    return tool.startswith("pentest.") or tool.startswith("fs.write") or tool in ("system.reboot", "system.shutdown")


def legacy_irreversible(tool: str, classification: Optional[Dict[str, Any]] = None) -> bool:
    """``agent_loop_policy.is_irreversible`` (name rule plus classifier C-3)."""
    from aiosh_mcp.agent_loop_policy import is_irreversible
    return bool(is_irreversible(tool, classification or {}))


def legacy_scope(tool: str) -> ScopeKind:
    """``audit_client.grant_check``: network targets for pentest./network. names, paths otherwise."""
    return ScopeKind.NETWORK if tool.startswith(NETWORK_PREFIXES) else ScopeKind.PATH


def _normal(value: str) -> str:
    return unicodedata.normalize("NFKC", value).strip().lower()


def intended_mode() -> str:
    """The mode the operator asked for in the environment; never raises.

    T-03379 #2: an unrecognised non-empty value (a typo such as ``strct``) is read as **strict** (fail closed)
    and reported once, instead of silently falling back to legacy-only rules. Unset or empty means shadow.
    """
    raw = os.environ.get(ENV_MODE, "")
    value = _normal(raw) if isinstance(raw, str) else ""
    if value and value not in MODES:
        _warn_once("mode", f"{ENV_MODE}={raw[:32]!r} is not one of {', '.join(MODES)}; using strict (fail closed)")
    # T-03406: env, config file and default combined, strictest wins (TOOLREGCONF-INV1); never raises.
    from aiosh_mcp.tool_registry_config import process_config
    return process_config()["config"]["mode"]       # one resolution per process (T-03409 #4, #5)


def _mode(mode: Optional[str]) -> str:
    if mode is None:
        return intended_mode()
    value = _normal(mode) if isinstance(mode, str) else mode
    if value not in MODES:          # an explicit bad argument is a programming error
        raise ToolServiceError(TOOLSVC_ERR_MODE, f"mode must be one of {', '.join(MODES)}")
    return value


_WARNED: set = set()


def _stderr_line(text: str) -> None:
    """Writes one line to stderr; never to stdout (the MCP JSON-RPC channel), never raises (T-03379 #7)."""
    stream = sys.stderr
    if stream is None or stream is sys.stdout:
        return
    try:
        print(text, file=stream, flush=True)
    except (OSError, ValueError):
        pass


def _warn_once(key: str, message: str) -> None:
    if key not in _WARNED:
        _WARNED.add(key)
        _stderr_line(f"aiosh-mcp: tool registry: {message}")


def _c3(classification: Any) -> bool:
    """Classifier C-3 flag, only from a well-formed result (T-03377: decide() must never raise on odd shapes)."""
    flags = classification.get("c_flags") if isinstance(classification, dict) else None
    return isinstance(flags, dict) and flags.get("c3") is True


def _hash(name: str) -> str:
    return hmac.new(_SAMPLE_KEY, name.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()[:12]


class ToolRegistryService:
    """Pure, per-process decision service (spec §2). Thread-safe counters; no I/O."""

    def __init__(self, catalog: Optional[ToolCatalog] = None, mode: Optional[str] = None) -> None:
        self._mode = _mode(mode)
        self._catalog = catalog if catalog is not None else default_catalog()
        self._lock = threading.Lock()
        self._decisions = 0
        self._unregistered = 0
        self._by_kind: Dict[str, int] = {k: 0 for k in DISAGREEMENT_KINDS}
        self._samples: List[str] = []
        from aiosh_mcp.tool_registry_config import process_config
        self._max_samples = int(process_config()["config"]["unregistered_samples"])

    @property
    def mode(self) -> str:
        return self._mode

    def decide(self, tool: Any, target: Any = None, classification: Optional[Dict[str, Any]] = None,
               require_grant: bool = False) -> ToolDecision:
        name = tool if type(tool) is str else ""
        entry = self._catalog.resolve(tool)
        profile = entry or self._catalog.profile(tool)
        c3 = _c3(classification)

        leg_grant = legacy_requires_grant(name) or bool(require_grant)
        leg_irrev = legacy_irreversible(name)
        leg_scope = legacy_scope(name)
        scopes = {leg_scope} | ({profile.scope_kind} if profile.scope_kind is not ScopeKind.NONE else set())

        disagreements = []
        if entry is None:
            disagreements.append("unregistered")
        if profile.requires_grant != leg_grant:
            disagreements.append("grant")
        if profile.irreversible != leg_irrev:
            disagreements.append("irreversible")
        if profile.scope_kind is not ScopeKind.NONE and profile.scope_kind is not leg_scope:
            disagreements.append("scope")

        decision = ToolDecision(
            canonical=profile.canonical, registered=entry is not None,
            requires_grant=profile.requires_grant or leg_grant,                                # TOOLSVC-INV1
            irreversible=profile.irreversible or leg_irrev or irreversible_by_name(name) or c3,
            scope_kinds=tuple(sorted(scopes, key=lambda s: s.value)),
            disagreements=tuple(sorted(disagreements)), mode=self._mode)
        self._count(decision, name)
        return decision

    def _count(self, decision: ToolDecision, name: str) -> None:
        with self._lock:
            self._decisions += 1
            for kind in decision.disagreements:
                self._by_kind[kind] += 1
            if not decision.registered:
                self._unregistered += 1
                h = _hash(name)
                if len(self._samples) < self._max_samples and h not in self._samples:
                    self._samples.append(h)

    def enforcement(self, decision: ToolDecision) -> Dict[str, Any]:
        """What strict mode adds to the legacy verdict (combined by OR); nothing in shadow mode (TOOLSVC-INV2/5)."""
        if self._mode != "strict":
            return {}
        return {"requires_grant": decision.requires_grant, "irreversible": decision.irreversible,
                "scope_kinds": tuple(s.value for s in decision.scope_kinds)}

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {"mode": self._mode, "decisions": self._decisions, "unregistered": self._unregistered,
                    "disagreements": dict(self._by_kind), "unregistered_samples": list(self._samples),
                    "catalog_entries": len(self._catalog)}


_REPORTED: set = set()
_REPORT_LOCK = threading.Lock()
_REPORT_STATE = {"lines": 0, "suppressed": 0}


def report(decision: ToolDecision, tool: Any, surface: str) -> None:
    """At most one masked JSON line on stderr per distinct disagreement, and at most ``MAX_REPORT_LINES`` per
    process (TOOLSVC-INV3: never an audit row; T-03379 #1: never enough output to block on a full pipe)."""
    if not decision.disagreements:
        return
    from aiosh_mcp.agent_loop_data_model import mask_secrets
    shown = mask_secrets(tool if type(tool) is str else repr(type(tool)))[:MAX_LOGGED_TOOL_LEN]
    key = (surface, shown, decision.disagreements)
    with _REPORT_LOCK:
        if key in _REPORTED:
            return
        cap = _report_cap()
        if _REPORT_STATE["lines"] >= cap:
            _REPORT_STATE["suppressed"] += 1
            return
        _REPORTED.add(key)
        _REPORT_STATE["lines"] += 1
        last = _REPORT_STATE["lines"] == cap
    line = {"event": LOG_EVENT, "surface": surface, "tool": shown,
            # T-03379 #5: canonical can be the raw (unregistered) name, so it is masked too
            "canonical": mask_secrets(decision.canonical)[:MAX_LOGGED_TOOL_LEN],
            "disagreements": list(decision.disagreements), "mode": decision.mode}
    if last:
        line["note"] = f"report limit ({cap}) reached; further disagreements are counted in stats only"
    _stderr_line(json.dumps(line, ensure_ascii=True))


def _report_cap() -> int:
    from aiosh_mcp.tool_registry_config import process_config
    return int(process_config()["config"]["report_max_lines"])


def report_stats() -> Dict[str, int]:
    with _REPORT_LOCK:
        return dict(_REPORT_STATE)


_SERVICE: Optional[ToolRegistryService] = None
_SERVICE_LOCK = threading.Lock()


_SERVICE_ERROR: Optional[BaseException] = None


def service() -> ToolRegistryService:
    """Process-wide instance built once from the default catalog and the env mode (fixed at first use, like
    the rest of the process config). A failed build is remembered and re-raised, not retried per call."""
    global _SERVICE, _SERVICE_ERROR
    if _SERVICE is None:
        with _SERVICE_LOCK:
            if _SERVICE is None:
                if _SERVICE_ERROR is not None:
                    raise _SERVICE_ERROR
                try:
                    _SERVICE = ToolRegistryService()
                except Exception as exc:
                    _SERVICE_ERROR = exc
                    raise
    return _SERVICE
