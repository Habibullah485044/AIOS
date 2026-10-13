"""Incident Response Runbooks configuration — MCP/API surface (T-03005 SCAFFOLD).

Contract: ``docs/SPEC-INCIDENT-RUNBOOK-CONFIG.md`` (normative).
Research: ``docs/tasks/evidence/T-03003-research.md``.

SCAFFOLD STATUS (T-03005): constants, defaults and bounds are real and
importable; every behavioral body raises ``NotImplementedError`` and
fails loudly. Implementation lands in T-03006.

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


def resolve_runbook_config(
    config_path: str | None = None,
    catalog_path: str | None = None,
    max_active_sessions: int | None = None,
    max_catalog_file_bytes: int | None = None,
    default_step_timeout_seconds: int | None = None,
    require_operator_confirmation: bool | None = None,
) -> RunbookConfig:
    """Scaffold implementation raises NotImplementedError for T-03006."""
    raise NotImplementedError("resolve_runbook_config scaffold - pending T-03006 implementation")
