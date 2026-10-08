"""Compliance Mapping configuration — MCP/API surface (T-02905 SCAFFOLD).

Contract: ``docs/tasks/evidence/T-02904-spec.md`` (normative).
Research: ``docs/tasks/evidence/T-02903-configuration-research.md``.

SCAFFOLD STATUS (T-02905): constants, defaults and bounds are real and
importable; every behavioral body raises ``NotImplementedError`` and
fails loudly. Implementation lands in T-02906.

Parity contract: field names, bounds and error codes mirror
``aiosh-core/src/compliance_config.rs`` byte-for-byte (spec §2 — one
resolved config on both substrates).
"""

from __future__ import annotations

import os
from typing import Any

# --- Constants (parity with compliance_config.rs) ---------------------------

#: Config file hard cap, 64 KiB (spec §5.1) — independent of the 1 MiB
#: store cap, so a malicious config cannot pre-allocate (CWE-400).
MAX_CONFIG_FILE_BYTES = 64 * 1024

#: Default config path (spec §3.2 level 3, T-02903 decision D-2).
DEFAULT_CONFIG_PATH = "docs/compliance_config.json"

#: Level-2 overrides in the precedence ladder (spec §3.2).
ENV_COMPLIANCE_CONFIG = "AIOSH_COMPLIANCE_CONFIG"
ENV_COMPLIANCE_MAP_PATH = "AIOSH_COMPLIANCE_MAP_PATH"

#: ``max_store_file_bytes`` default / bounds (spec §3.1, §5.2).
DEFAULT_MAX_STORE_FILE_BYTES = 1024 * 1024  # 1 MiB
MIN_MAX_STORE_FILE_BYTES = 4096
MAX_MAX_STORE_FILE_BYTES = 16 * 1024 * 1024  # 16 MiB

#: ``max_entries`` default / bounds (spec §3.1).
DEFAULT_MAX_ENTRIES = 1024
MIN_MAX_ENTRIES = 1
MAX_MAX_ENTRIES = 4096

#: Longest accepted env/config path value — the hygiene predicate bound
#: from spec §4.3 (mirrors ``threat_model_config.rs:139``).
MAX_CONFIG_PATH_LEN = 1024

# Error codes (spec §4.2). AIOS-specific ⟦AIOS⟧, following the
# ``THREATCONF_ERR_*`` naming already used by ``threat_model_config``.
COMPLIANCECONF_ERR_PATH_TRAVERSAL = "COMPLIANCECONF_ERR_PATH_TRAVERSAL"
COMPLIANCECONF_ERR_FILE_SIZE = "COMPLIANCECONF_ERR_FILE_SIZE"
COMPLIANCECONF_ERR_PARSE = "COMPLIANCECONF_ERR_PARSE"
COMPLIANCECONF_ERR_BOUNDS = "COMPLIANCECONF_ERR_BOUNDS"
COMPLIANCECONF_ERR_IO = "COMPLIANCECONF_ERR_IO"
COMPLIANCECONF_ERR_VALIDATION = "COMPLIANCECONF_ERR_VALIDATION"

#: Where a resolved value came from (spec §3.3 ``source`` field).
CONFIG_SOURCES = ("argument", "env", "file", "default", "env_invalid",
                  "config_invalid")

_NOT_IMPLEMENTED = "T-02906: aiosh_mcp.compliance_config.{}"


# --- Defaults (spec §3.1) ---------------------------------------------------

def default_config() -> dict[str, Any]:
    """Return the spec §3.1 default configuration.

    Real (not a stub): the defaults are the contract the resolver falls
    back to, and tests assert them before T-02906 lands.
    """
    # Imported lazily so this module has no import-time dependency on the
    # store module beyond the path constant it reuses (spec §2 REUSED).
    from .compliance import DEFAULT_STORE_PATH
    return {
        "version": "1.0.0",
        "store_path": DEFAULT_STORE_PATH,
        "max_store_file_bytes": DEFAULT_MAX_STORE_FILE_BYTES,
        "max_entries": DEFAULT_MAX_ENTRIES,
        "audit_all_queries": False,
        # spec §5.4: must never load as False — mutation auditing cannot
        # be silently disabled.
        "audit_all_mutations": True,
    }


# --- Scaffolding: behavioral bodies fail loudly (T-02906) -------------------

def load_config(path: str | None = None) -> dict[str, Any]:
    """Read a config file with the 64 KiB cap applied before parsing."""
    raise NotImplementedError(_NOT_IMPLEMENTED.format("load_config"))


def from_env() -> dict[str, Any]:
    """Levels 3-4 of the precedence ladder (spec §3.2): env path if it
    passes the hygiene predicate, else default path if present, else
    defaults. Never raises on bad input (T-02903 F-7 precedent)."""
    raise NotImplementedError(_NOT_IMPLEMENTED.format("from_env"))


def resolve(arg_path: str | None = None,
            arg_config: str | None = None) -> dict[str, Any]:
    """Full 4-level resolution: argument → env → file → default.

    Returns ``{"config": {...}, "source": {key: origin}}`` per spec §4.1.
    """
    raise NotImplementedError(_NOT_IMPLEMENTED.format("resolve"))


def validate(config: dict[str, Any]) -> dict[str, Any]:
    """Bounds + hygiene validation (spec §3.1, §4.2).

    Inert fields clamp; security-relevant fields fail closed
    (T-02903 decision D-5).
    """
    raise NotImplementedError(_NOT_IMPLEMENTED.format("validate"))


def hygiene_ok(value: str) -> bool:
    """CWE-15 gate for env-supplied paths (spec §4.3): non-empty, no
    ``..``, no control characters, ``len <= MAX_CONFIG_PATH_LEN``."""
    raise NotImplementedError(_NOT_IMPLEMENTED.format("hygiene_ok"))


__all__ = [
    "MAX_CONFIG_FILE_BYTES", "DEFAULT_CONFIG_PATH",
    "ENV_COMPLIANCE_CONFIG", "ENV_COMPLIANCE_MAP_PATH",
    "DEFAULT_MAX_STORE_FILE_BYTES", "MIN_MAX_STORE_FILE_BYTES",
    "MAX_MAX_STORE_FILE_BYTES",
    "DEFAULT_MAX_ENTRIES", "MIN_MAX_ENTRIES", "MAX_MAX_ENTRIES",
    "MAX_CONFIG_PATH_LEN",
    "COMPLIANCECONF_ERR_PATH_TRAVERSAL", "COMPLIANCECONF_ERR_FILE_SIZE",
    "COMPLIANCECONF_ERR_PARSE", "COMPLIANCECONF_ERR_BOUNDS",
    "COMPLIANCECONF_ERR_IO", "COMPLIANCECONF_ERR_VALIDATION",
    "CONFIG_SOURCES",
    "default_config", "load_config", "from_env", "resolve", "validate",
    "hygiene_ok",
]
