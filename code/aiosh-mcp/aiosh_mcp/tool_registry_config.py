"""Tool Registry & Taxonomy configuration (T-03405 scaffold).

Spec: docs/tasks/evidence/T-03404-spec.md. Three tunables (mode, report_max_lines, unregistered_samples)
from argument / env / config file / default. The mode is strictest-wins; security policy is locked and not
representable (TOOLREGCONF-INV1..TOOLREGCONF-INV4). Resolving never raises, writes nothing, audits nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

TOOLREGCONF_ERR_IO = "TOOLREGCONF_ERR_IO"
TOOLREGCONF_ERR_FILE_SIZE = "TOOLREGCONF_ERR_FILE_SIZE"
TOOLREGCONF_ERR_PARSE = "TOOLREGCONF_ERR_PARSE"
TOOLREGCONF_ERR_UNKNOWN_KEY = "TOOLREGCONF_ERR_UNKNOWN_KEY"
TOOLREGCONF_ERR_LOCKED = "TOOLREGCONF_ERR_LOCKED"
TOOLREGCONF_ERR_BOUNDS = "TOOLREGCONF_ERR_BOUNDS"
TOOLREGCONF_ERR_ENV = "TOOLREGCONF_ERR_ENV"

ENV_CONFIG = "AIOSH_TOOL_REGISTRY_CONFIG"
DEFAULT_CONFIG_PATH = "docs/tool_registry_config.json"
MAX_CONFIG_FILE_BYTES = 64 * 1024
MAX_CONFIG_PATH_LEN = 1024
MODES = ("shadow", "strict")


@dataclass(frozen=True)
class IntField:
    default: int
    lo: int
    hi: int
    env: str


#: Numeric tunables (spec §1). ``mode`` is handled separately (strictest wins).
FIELDS: Dict[str, IntField] = {
    "report_max_lines": IntField(32, 0, 1000, "AIOSH_TOOL_REGISTRY_REPORT_MAX_LINES"),
    "unregistered_samples": IntField(50, 0, 200, "AIOSH_TOOL_REGISTRY_UNREGISTERED_SAMPLES"),
}
ENV_MODE = "AIOSH_TOOL_REGISTRY_MODE"
#: Security policy: not representable in configuration (TOOLREGCONF-INV2).
LOCKED_KEYS: Tuple[str, ...] = ("catalog", "entries", "read_only_hint_categories", "grant_params", "path_params",
                                "irreversible_names", "irreversible_prefixes")


def resolve(arg_mode: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Resolved configuration with sources and errors (spec §3). Never raises."""
    raise NotImplementedError("T-03406: resolve")


def process_config() -> Dict[str, Any]:
    """Resolved once per process."""
    raise NotImplementedError("T-03406: process_config")


def reset_process_config() -> None:
    """For tests: forget the per-process resolution."""
    raise NotImplementedError("T-03406: reset_process_config")
