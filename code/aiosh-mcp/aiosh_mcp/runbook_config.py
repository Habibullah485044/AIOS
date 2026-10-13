"""Incident Response Runbooks configuration — MCP/API surface (T-03006).

Contract: ``docs/SPEC-INCIDENT-RUNBOOK-CONFIG.md`` (normative).
Research: ``docs/tasks/evidence/T-03003-research.md``.

Parity contract: field names, bounds and error codes mirror
``aiosh-core/src/runbook_config.rs`` byte-for-byte.
"""

from __future__ import annotations

import json
import os
from typing import Any

# Hard cap on configuration JSON file: 64 KiB.
MAX_CONFIG_FILE_BYTES = 64 * 1024

# Default paths
DEFAULT_CONFIG_PATH = "docs/runbook_config.json"
DEFAULT_CATALOG_PATH = "docs/runbook_catalog.json"

# Environment variables
ENV_RUNBOOK_CONFIG = "AIOSH_RUNBOOK_CONFIG"
ENV_RUNBOOK_CATALOG_PATH = "AIOSH_RUNBOOK_CATALOG_PATH"
ENV_RUNBOOK_MAX_SESSIONS = "AIOSH_RUNBOOK_MAX_SESSIONS"
ENV_RUNBOOK_STEP_TIMEOUT = "AIOSH_RUNBOOK_STEP_TIMEOUT"
ENV_RUNBOOK_REQUIRE_CONFIRMATION = "AIOSH_RUNBOOK_REQUIRE_CONFIRMATION"

# Defaults and boundary clamping constants
DEFAULT_MAX_ACTIVE_SESSIONS = 1000
MIN_MAX_ACTIVE_SESSIONS = 1
MAX_MAX_ACTIVE_SESSIONS = 10000

DEFAULT_MAX_CATALOG_FILE_BYTES = 1024 * 1024  # 1 MiB
MIN_MAX_CATALOG_FILE_BYTES = 4096
MAX_MAX_CATALOG_FILE_BYTES = 16 * 1024 * 1024  # 16 MiB

DEFAULT_STEP_TIMEOUT_SECONDS = 3600  # 1 hour
MIN_STEP_TIMEOUT_SECONDS = 1
MAX_STEP_TIMEOUT_SECONDS = 86400  # 24 hours

MAX_CONFIG_PATH_LEN = 1024

# Error codes
RUNBOOKCONF_ERR_PATH_TRAVERSAL = "RUNBOOKCONF_ERR_PATH_TRAVERSAL"
RUNBOOKCONF_ERR_FILE_SIZE = "RUNBOOKCONF_ERR_FILE_SIZE"
RUNBOOKCONF_ERR_PARSE = "RUNBOOKCONF_ERR_PARSE"
RUNBOOKCONF_ERR_BOUNDS = "RUNBOOKCONF_ERR_BOUNDS"
RUNBOOKCONF_ERR_IO = "RUNBOOKCONF_ERR_IO"
RUNBOOKCONF_ERR_VALIDATION = "RUNBOOKCONF_ERR_VALIDATION"

CONFIG_SOURCES = (
    "argument",
    "env",
    "file",
    "default",
    "env_invalid",
    "config_invalid",
)


def hygiene_ok(value: str) -> bool:
    """CWE-15 gate for paths: non-empty, no '..', no control chars, bounded."""
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


def validate_config_path(path: str) -> str:
    """Validate path string against length and traversal limits."""
    trimmed = path.strip()
    if not trimmed:
        raise ValueError(f"{RUNBOOKCONF_ERR_VALIDATION}: Path cannot be empty")
    if len(trimmed) > MAX_CONFIG_PATH_LEN:
        raise ValueError(f"{RUNBOOKCONF_ERR_BOUNDS}: Path length {len(trimmed)} exceeds maximum {MAX_CONFIG_PATH_LEN}")
    if ".." in trimmed:
        raise ValueError(f"{RUNBOOKCONF_ERR_PATH_TRAVERSAL}: Path traversal '..' strictly prohibited")
    return trimmed


class RunbookConfig:
    """Resolved Incident Response Runbooks configuration."""

    def __init__(
        self,
        catalog_path: str = DEFAULT_CATALOG_PATH,
        max_active_sessions: int = DEFAULT_MAX_ACTIVE_SESSIONS,
        max_catalog_file_bytes: int = DEFAULT_MAX_CATALOG_FILE_BYTES,
        default_step_timeout_seconds: int = DEFAULT_STEP_TIMEOUT_SECONDS,
        require_operator_confirmation: bool = True,
        sources: dict[str, str] | None = None,
    ):
        self.catalog_path = catalog_path
        self.max_active_sessions = max_active_sessions
        self.max_catalog_file_bytes = max_catalog_file_bytes
        self.default_step_timeout_seconds = default_step_timeout_seconds
        self.require_operator_confirmation = require_operator_confirmation
        self.sources = sources or {
            "catalog_path": "default",
            "max_active_sessions": "default",
            "max_catalog_file_bytes": "default",
            "default_step_timeout_seconds": "default",
            "require_operator_confirmation": "default",
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "catalog_path": self.catalog_path,
            "max_active_sessions": self.max_active_sessions,
            "max_catalog_file_bytes": self.max_catalog_file_bytes,
            "default_step_timeout_seconds": self.default_step_timeout_seconds,
            "require_operator_confirmation": self.require_operator_confirmation,
            "sources": dict(self.sources),
        }


def _read_raw(path: str) -> dict[str, Any]:
    """Read a config file with 64 KiB cap applied before parsing (CWE-400)."""
    trimmed = validate_config_path(path)
    if not os.path.exists(trimmed):
        return {}
    if os.path.isdir(trimmed):
        raise ValueError(f"{RUNBOOKCONF_ERR_IO}: Config path is a directory: {trimmed}")
    try:
        size = os.path.getsize(trimmed)
    except OSError as e:
        raise ValueError(f"{RUNBOOKCONF_ERR_IO}: Cannot stat config file {trimmed}: {e}") from e
    if size > MAX_CONFIG_FILE_BYTES:
        raise ValueError(f"{RUNBOOKCONF_ERR_FILE_SIZE}: Config file {trimmed} is {size} bytes, limit {MAX_CONFIG_FILE_BYTES}")
    try:
        with open(trimmed, "r", encoding="utf-8") as f:
            raw = f.read(MAX_CONFIG_FILE_BYTES + 1)
    except UnicodeDecodeError as e:
        raise ValueError(f"{RUNBOOKCONF_ERR_PARSE}: Non-UTF-8 config at {trimmed}: {e}") from e
    except OSError as e:
        raise ValueError(f"{RUNBOOKCONF_ERR_IO}: Cannot read config file {trimmed}: {e}") from e
    if len(raw.encode("utf-8")) > MAX_CONFIG_FILE_BYTES:
        raise ValueError(f"{RUNBOOKCONF_ERR_FILE_SIZE}: Config file {trimmed} exceeds limit {MAX_CONFIG_FILE_BYTES}")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"{RUNBOOKCONF_ERR_PARSE}: Malformed config at {trimmed}: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"{RUNBOOKCONF_ERR_PARSE}: Config root must be a JSON object: {trimmed}")
    return data


def resolve_runbook_config(
    config_path: str | None = None,
    catalog_path: str | None = None,
    max_active_sessions: int | None = None,
    max_catalog_file_bytes: int | None = None,
    default_step_timeout_seconds: int | None = None,
    require_operator_confirmation: bool | None = None,
) -> RunbookConfig:
    """Resolve Incident Response Runbooks configuration via 4-level precedence ladder.

    Level 1: CLI / Argument Overrides
    Level 2: Environment Variables
    Level 3: Configuration File (Explicit / Env / Default)
    Level 4: Built-in Defaults
    """
    resolved_catalog_path = DEFAULT_CATALOG_PATH
    resolved_max_sessions = DEFAULT_MAX_ACTIVE_SESSIONS
    resolved_max_file_bytes = DEFAULT_MAX_CATALOG_FILE_BYTES
    resolved_timeout = DEFAULT_STEP_TIMEOUT_SECONDS
    resolved_require_confirm = True

    sources: dict[str, str] = {
        "catalog_path": "default",
        "max_active_sessions": "default",
        "max_catalog_file_bytes": "default",
        "default_step_timeout_seconds": "default",
        "require_operator_confirmation": "default",
    }

    # Level 3: Configuration File
    target_config_path = None
    if config_path and hygiene_ok(config_path):
        target_config_path = config_path
    elif ENV_RUNBOOK_CONFIG in os.environ and hygiene_ok(os.environ[ENV_RUNBOOK_CONFIG]):
        target_config_path = os.environ[ENV_RUNBOOK_CONFIG]
    elif os.path.exists(DEFAULT_CONFIG_PATH):
        target_config_path = DEFAULT_CONFIG_PATH

    if target_config_path:
        file_data = _read_raw(target_config_path)
        if "catalog_path" in file_data:
            cpath = str(file_data["catalog_path"])
            if hygiene_ok(cpath):
                resolved_catalog_path = cpath
                sources["catalog_path"] = "file"
            else:
                sources["catalog_path"] = "config_invalid"
        if "max_active_sessions" in file_data:
            try:
                ms = int(file_data["max_active_sessions"])
                resolved_max_sessions = max(MIN_MAX_ACTIVE_SESSIONS, min(ms, MAX_MAX_ACTIVE_SESSIONS))
                sources["max_active_sessions"] = "file"
            except (ValueError, TypeError):
                sources["max_active_sessions"] = "config_invalid"
        if "max_catalog_file_bytes" in file_data:
            try:
                mf = int(file_data["max_catalog_file_bytes"])
                resolved_max_file_bytes = max(MIN_MAX_CATALOG_FILE_BYTES, min(mf, MAX_MAX_CATALOG_FILE_BYTES))
                sources["max_catalog_file_bytes"] = "file"
            except (ValueError, TypeError):
                sources["max_catalog_file_bytes"] = "config_invalid"
        if "default_step_timeout_seconds" in file_data:
            try:
                to = int(file_data["default_step_timeout_seconds"])
                resolved_timeout = max(MIN_STEP_TIMEOUT_SECONDS, min(to, MAX_STEP_TIMEOUT_SECONDS))
                sources["default_step_timeout_seconds"] = "file"
            except (ValueError, TypeError):
                sources["default_step_timeout_seconds"] = "config_invalid"
        if "require_operator_confirmation" in file_data:
            resolved_require_confirm = bool(file_data["require_operator_confirmation"])
            sources["require_operator_confirmation"] = "file"

    # Level 2: Environment Variables
    if ENV_RUNBOOK_CATALOG_PATH in os.environ:
        env_cat = os.environ[ENV_RUNBOOK_CATALOG_PATH]
        if hygiene_ok(env_cat):
            resolved_catalog_path = env_cat.strip()
            sources["catalog_path"] = "env"
        else:
            sources["catalog_path"] = "env_invalid"

    if ENV_RUNBOOK_MAX_SESSIONS in os.environ:
        try:
            val = int(os.environ[ENV_RUNBOOK_MAX_SESSIONS])
            resolved_max_sessions = max(MIN_MAX_ACTIVE_SESSIONS, min(val, MAX_MAX_ACTIVE_SESSIONS))
            sources["max_active_sessions"] = "env"
        except (ValueError, TypeError):
            sources["max_active_sessions"] = "env_invalid"

    if ENV_RUNBOOK_STEP_TIMEOUT in os.environ:
        try:
            val = int(os.environ[ENV_RUNBOOK_STEP_TIMEOUT])
            resolved_timeout = max(MIN_STEP_TIMEOUT_SECONDS, min(val, MAX_STEP_TIMEOUT_SECONDS))
            sources["default_step_timeout_seconds"] = "env"
        except (ValueError, TypeError):
            sources["default_step_timeout_seconds"] = "env_invalid"

    if ENV_RUNBOOK_REQUIRE_CONFIRMATION in os.environ:
        raw_val = os.environ[ENV_RUNBOOK_REQUIRE_CONFIRMATION].strip().lower()
        if raw_val in ("1", "true", "yes", "on"):
            resolved_require_confirm = True
            sources["require_operator_confirmation"] = "env"
        elif raw_val in ("0", "false", "no", "off"):
            resolved_require_confirm = False
            sources["require_operator_confirmation"] = "env"
        else:
            sources["require_operator_confirmation"] = "env_invalid"

    # Level 1: Argument Overrides
    if catalog_path is not None:
        trimmed_cat = validate_config_path(catalog_path)
        resolved_catalog_path = trimmed_cat
        sources["catalog_path"] = "argument"

    if max_active_sessions is not None:
        resolved_max_sessions = max(MIN_MAX_ACTIVE_SESSIONS, min(int(max_active_sessions), MAX_MAX_ACTIVE_SESSIONS))
        sources["max_active_sessions"] = "argument"

    if max_catalog_file_bytes is not None:
        resolved_max_file_bytes = max(MIN_MAX_CATALOG_FILE_BYTES, min(int(max_catalog_file_bytes), MAX_MAX_CATALOG_FILE_BYTES))
        sources["max_catalog_file_bytes"] = "argument"

    if default_step_timeout_seconds is not None:
        resolved_timeout = max(MIN_STEP_TIMEOUT_SECONDS, min(int(default_step_timeout_seconds), MAX_STEP_TIMEOUT_SECONDS))
        sources["default_step_timeout_seconds"] = "argument"

    if require_operator_confirmation is not None:
        resolved_require_confirm = bool(require_operator_confirmation)
        sources["require_operator_confirmation"] = "argument"

    return RunbookConfig(
        catalog_path=resolved_catalog_path,
        max_active_sessions=resolved_max_sessions,
        max_catalog_file_bytes=resolved_max_file_bytes,
        default_step_timeout_seconds=resolved_timeout,
        require_operator_confirmation=resolved_require_confirm,
        sources=sources,
    )
