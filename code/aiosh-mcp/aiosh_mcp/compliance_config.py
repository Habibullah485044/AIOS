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

import json
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


def hygiene_ok(value: str) -> bool:
    """CWE-15 gate for env-supplied paths (spec §4.3): non-empty, no
    ``..``, no control characters, ``len <= MAX_CONFIG_PATH_LEN``.

    Total predicate — returns ``bool`` for any input, never raises.
    """
    if not isinstance(value, str):
        return False
    v = value.strip()
    if not v:
        return False
    if len(v) > MAX_CONFIG_PATH_LEN:
        return False
    if ".." in v:
        return False
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in v):
        return False
    return True


def validate(config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Bounds + hygiene validation (spec §3.1, §4.2).

    Inert fields (``max_entries``, ``max_store_file_bytes``) clamp to their
    declared bounds; security-relevant fields fail closed downstream via
    ``validate_path`` (T-02903 decision D-5). Missing keys fall back to
    the spec §3.1 defaults.
    """
    if config is not None and not isinstance(config, dict):
        raise ValueError(
            f"{COMPLIANCECONF_ERR_VALIDATION}: config must be an object")
    merged = default_config()
    for key, value in (config or {}).items():
        if key in merged and value is not None:
            merged[key] = value

    # version / store_path: non-empty strings or defaults.
    version = merged.get("version")
    if not isinstance(version, str) or not version.strip():
        merged["version"] = default_config()["version"]
    store = merged.get("store_path")
    if not isinstance(store, str) or not store.strip():
        merged["store_path"] = default_config()["store_path"]

    # Inert numeric fields clamp (spec §4.2 row: "out of bounds -> clamp").
    try:
        entries = int(merged.get("max_entries"))
    except (TypeError, ValueError):
        entries = DEFAULT_MAX_ENTRIES
    merged["max_entries"] = max(MIN_MAX_ENTRIES,
                                min(entries, MAX_MAX_ENTRIES))

    try:
        size = int(merged.get("max_store_file_bytes"))
    except (TypeError, ValueError):
        size = DEFAULT_MAX_STORE_FILE_BYTES
    merged["max_store_file_bytes"] = max(MIN_MAX_STORE_FILE_BYTES,
                                         min(size, MAX_MAX_STORE_FILE_BYTES))

    merged["audit_all_queries"] = bool(merged.get("audit_all_queries", False))
    # spec §5.4: mutation auditing can never be disabled by config.
    merged["audit_all_mutations"] = True
    return merged


def _read_raw(path: str) -> dict[str, Any]:
    """Read a config file with the 64 KiB cap applied *before* parsing
    (CWE-400), raising the spec §4.2 error codes. Missing file -> ``{}``.
    """
    if not isinstance(path, str) or not path:
        raise ValueError(
            f"{COMPLIANCECONF_ERR_PATH_TRAVERSAL}: path cannot be empty")
    if not os.path.exists(path):
        return {}
    if os.path.isdir(path):
        raise ValueError(
            f"{COMPLIANCECONF_ERR_IO}: config path is a directory: {path}")
    try:
        size = os.path.getsize(path)
    except OSError as e:
        raise ValueError(
            f"{COMPLIANCECONF_ERR_IO}: cannot stat config file {path}: {e}") from e
    if size > MAX_CONFIG_FILE_BYTES:
        raise ValueError(
            f"{COMPLIANCECONF_ERR_FILE_SIZE}: config file {path} is {size} "
            f"bytes, limit {MAX_CONFIG_FILE_BYTES}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read(MAX_CONFIG_FILE_BYTES + 1)
    except UnicodeDecodeError as e:
        raise ValueError(
            f"{COMPLIANCECONF_ERR_PARSE}: non-UTF-8 config at {path}: {e}") from e
    except OSError as e:
        raise ValueError(
            f"{COMPLIANCECONF_ERR_IO}: cannot read config file {path}: {e}") from e
    if len(raw.encode("utf-8")) > MAX_CONFIG_FILE_BYTES:
        raise ValueError(
            f"{COMPLIANCECONF_ERR_FILE_SIZE}: config file {path} exceeds "
            f"{MAX_CONFIG_FILE_BYTES} bytes")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(
            f"{COMPLIANCECONF_ERR_PARSE}: malformed config at {path}: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(
            f"{COMPLIANCECONF_ERR_PARSE}: config root must be an object: {path}")
    return data


def load_config(path: str | None = None) -> dict[str, Any]:
    """Read a config file with the 64 KiB cap applied before parsing.

    A **missing** file is not an error (spec §4.2 last row): defaults are
    returned. Malformed / oversized files fail closed with
    ``COMPLIANCECONF_ERR_PARSE`` / ``COMPLIANCECONF_ERR_FILE_SIZE``.
    """
    if path is None:
        path = os.environ.get(ENV_COMPLIANCE_CONFIG) or DEFAULT_CONFIG_PATH
    return validate(_read_raw(path))


def from_env() -> dict[str, Any]:
    """Levels 3-4 of the precedence ladder (spec §3.2): env path if it
    passes the hygiene predicate, else default path if present, else
    defaults. Never raises on bad input (T-02903 F-7 precedent)."""
    env_path = os.environ.get(ENV_COMPLIANCE_CONFIG)
    if env_path is not None:
        if hygiene_ok(env_path) and os.path.exists(env_path):
            try:
                return load_config(env_path)
            except ValueError:
                pass
        return default_config()
    if os.path.exists(DEFAULT_CONFIG_PATH):
        try:
            return load_config(DEFAULT_CONFIG_PATH)
        except ValueError:
            return default_config()
    return default_config()


def resolve(arg_path: str | None = None,
            arg_config: str | None = None) -> dict[str, Any]:
    """Full 4-level resolution: argument → env → file → default.

    Returns ``{"config": {...}, "source": {key: origin}}`` per spec §4.1,
    where origin is one of ``CONFIG_SOURCES``. An env value that fails the
    hygiene predicate is **rejected** (reported as ``env_invalid``) rather
    than applied (CWE-15, spec §4.3).
    """
    known = default_config()

    # --- Level 3: config file -------------------------------------------
    raw: dict[str, Any] = {}
    if arg_config is not None:
        if hygiene_ok(arg_config):
            raw = _read_raw(arg_config)
    else:
        env_cfg = os.environ.get(ENV_COMPLIANCE_CONFIG)
        if env_cfg is not None:
            if hygiene_ok(env_cfg):
                raw = _read_raw(env_cfg)
        elif os.path.exists(DEFAULT_CONFIG_PATH):
            raw = _read_raw(DEFAULT_CONFIG_PATH)

    cfg = dict(known)
    source = {key: "default" for key in known}
    for key, value in raw.items():
        if key in known:
            cfg[key] = value
            source[key] = "file"

    # --- Level 2: env store-path override --------------------------------
    raw_store = os.environ.get(ENV_COMPLIANCE_MAP_PATH)
    if raw_store is not None:
        if hygiene_ok(raw_store):
            cfg["store_path"] = raw_store
            source["store_path"] = "env"
        else:
            # Rejected, NOT applied — source records the rejection.
            source["store_path"] = "env_invalid"

    # --- Level 1: explicit argument (strongest) --------------------------
    # Applied unconditionally: an operator-supplied path must not be
    # silently replaced by the default when invalid — it flows to
    # ``validate_path``, which rejects it loudly. The hygiene gate is for
    # *env* values (CWE-15, spec §4.3), not explicit operator intent.
    if arg_path is not None:
        cfg["store_path"] = arg_path
        source["store_path"] = "argument"

    return {"config": validate(cfg), "source": source}


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
