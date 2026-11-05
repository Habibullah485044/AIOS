"""Tool Registry & Taxonomy core service (T-03375 scaffold / T-03376 impl).

Spec: docs/tasks/evidence/T-03374-spec.md. A pure decision service over the immutable catalog: for one tool
call it reports the canonical name, grant requirement, irreversibility and applicable scopes, and where the
catalog disagrees with the legacy name rules. Shadow mode (default) changes no enforcement; strict mode can
only tighten it (TOOLSVC-INV1..TOOLSVC-INV5).
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
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


def _mode(mode: Optional[str]) -> str:
    value = os.environ.get(ENV_MODE, DEFAULT_MODE) if mode is None else mode
    value = value.strip().lower() if isinstance(value, str) else value
    if value not in MODES:
        raise ToolServiceError(TOOLSVC_ERR_MODE, f"mode must be one of {', '.join(MODES)}")
    return value


def _c3(classification: Any) -> bool:
    """Classifier C-3 flag, only from a well-formed result (T-03377: decide() must never raise on odd shapes)."""
    flags = classification.get("c_flags") if isinstance(classification, dict) else None
    return isinstance(flags, dict) and flags.get("c3") is True


def _hash(name: str) -> str:
    return hashlib.sha256(name.encode("utf-8", "surrogatepass")).hexdigest()[:12]


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
            disagreements=tuple(disagreements), mode=self._mode)
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
                if len(self._samples) < MAX_UNREGISTERED_SAMPLES and h not in self._samples:
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


def report(decision: ToolDecision, tool: Any, surface: str) -> None:
    """One masked JSON line on stderr per disagreeing decision (TOOLSVC-INV3: never an audit row)."""
    if not decision.disagreements:
        return
    from aiosh_mcp.agent_loop_data_model import mask_secrets
    shown = mask_secrets(tool if type(tool) is str else repr(type(tool)))[:MAX_LOGGED_TOOL_LEN]
    line = {"event": LOG_EVENT, "surface": surface, "tool": shown, "canonical": decision.canonical,
            "disagreements": list(decision.disagreements), "mode": decision.mode}
    try:
        print(json.dumps(line, ensure_ascii=True), file=sys.stderr, flush=True)
    except (OSError, ValueError):
        pass                                 # a closed stderr must never break a tool call


_SERVICE: Optional[ToolRegistryService] = None
_SERVICE_LOCK = threading.Lock()


def service() -> ToolRegistryService:
    """Process-wide instance built once from the default catalog and the env mode."""
    global _SERVICE
    if _SERVICE is None:
        with _SERVICE_LOCK:
            if _SERVICE is None:
                _SERVICE = ToolRegistryService()
    return _SERVICE
