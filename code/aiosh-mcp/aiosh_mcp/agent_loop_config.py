"""Agent Loop Hardening configuration (T-03305 SCAFFOLD).

Contract: ``docs/tasks/evidence/T-03304-spec.md`` (normative).
Research: ``docs/tasks/evidence/T-03303-research.md``.

SCAFFOLD STATUS (T-03305): constants, field table, bounds and error codes are
real and importable; every behavioral body raises ``NotImplementedError`` and
fails loudly. Implementation lands in T-03306.

Precedence (spec §3): argument -> per-field env -> config file -> default,
then clamp. Security and audit controls are locked and not representable
(AGENTLOOPCONF-INV2).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from aiosh_mcp.agent_loop_data_model import LoopConfig

#: Config file hard cap, 64 KiB (CWE-400).
MAX_CONFIG_FILE_BYTES = 64 * 1024
#: Longest accepted env-supplied path (CWE-15 hygiene).
MAX_CONFIG_PATH_LEN = 1024
#: Optional default file; absence means defaults.
DEFAULT_CONFIG_PATH = "docs/agent_loop_config.json"
ENV_AGENT_LOOP_CONFIG = "AIOSH_AGENT_LOOP_CONFIG"

AGENTLOOPCONF_ERR_FILE_SIZE = "AGENTLOOPCONF_ERR_FILE_SIZE"
AGENTLOOPCONF_ERR_IO = "AGENTLOOPCONF_ERR_IO"
AGENTLOOPCONF_ERR_PARSE = "AGENTLOOPCONF_ERR_PARSE"
AGENTLOOPCONF_ERR_UNKNOWN_KEY = "AGENTLOOPCONF_ERR_UNKNOWN_KEY"
AGENTLOOPCONF_ERR_LOCKED = "AGENTLOOPCONF_ERR_LOCKED"
AGENTLOOPCONF_ERR_BOUNDS = "AGENTLOOPCONF_ERR_BOUNDS"
AGENTLOOPCONF_ERR_ENV = "AGENTLOOPCONF_ERR_ENV"

CONFIG_SOURCES = ("argument", "env", "file", "default", "env_invalid", "config_invalid")


@dataclass(frozen=True)
class FieldSpec:
    """One tunable: default, inclusive clamp bounds, numeric type and env override."""

    default: float
    lo: float
    hi: float
    kind: type
    env: str


FIELDS: Dict[str, FieldSpec] = {
    "default_max_iterations": FieldSpec(25, 1, 100, int, "AIOSH_AGENT_LOOP_MAX_ITERATIONS"),
    "default_max_total_tokens": FieldSpec(32768, 100, 1_000_000, int, "AIOSH_AGENT_LOOP_MAX_TOTAL_TOKENS"),
    "default_timeout_ms_per_step": FieldSpec(30000.0, 1000.0, 120000.0, float,
                                             "AIOSH_AGENT_LOOP_TIMEOUT_MS_PER_STEP"),
    "default_total_timeout_ms": FieldSpec(300000.0, 5000.0, 1_800_000.0, float,
                                          "AIOSH_AGENT_LOOP_TOTAL_TIMEOUT_MS"),
    "default_consecutive_failure_limit": FieldSpec(3, 1, 10, int, "AIOSH_AGENT_LOOP_CONSECUTIVE_FAILURE_LIMIT"),
    "registry_capacity": FieldSpec(256, 1, 256, int, "AIOSH_AGENT_LOOP_REGISTRY_CAPACITY"),
    "mcp_call_timeout_s": FieldSpec(15.0, 1.0, 60.0, float, "AIOSH_AGENT_LOOP_MCP_CALL_TIMEOUT_S"),
    "history_page_bytes": FieldSpec(1024 * 1024, 64 * 1024, 4 * 1024 * 1024, int,
                                    "AIOSH_AGENT_LOOP_HISTORY_PAGE_BYTES"),
    "snapshot_steps_tail": FieldSpec(100, 0, 1000, int, "AIOSH_AGENT_LOOP_SNAPSHOT_STEPS_TAIL"),
    "db_busy_timeout_ms": FieldSpec(5000, 100, 30000, int, "AIOSH_AGENT_LOOP_DB_BUSY_TIMEOUT_MS"),
}

#: Controls that config must never loosen (spec §2, AGENTLOOPCONF-INV2).
LOCKED_KEYS: Tuple[str, ...] = (
    "max_args_bytes", "max_args_depth", "max_action_intent_chars", "max_reason_chars",
    "max_tokens_per_turn", "tool_name_pattern", "max_token_chars", "require_grant", "audit_mutations",
)


def default_config() -> Dict[str, Any]:
    """Fresh dict of spec §2 defaults."""
    raise NotImplementedError("T-03306: default_config")


def hygiene_ok(value: Any) -> bool:
    """Total CWE-15 predicate for env-supplied paths; never raises."""
    raise NotImplementedError("T-03306: hygiene_ok")


def validate(config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge onto defaults and clamp; unknown/locked keys raise ValueError."""
    raise NotImplementedError("T-03306: validate")


def resolve(arg_config: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Full precedence ladder -> {"config", "source", "errors"}; never raises (AGENTLOOPCONF-INV1)."""
    raise NotImplementedError("T-03306: resolve")


def loop_config_for(loop_id: str, resolved: Optional[Dict[str, Any]] = None, **explicit: Any) -> LoopConfig:
    """LoopConfig from resolved defaults plus explicit per-call values (explicit wins)."""
    raise NotImplementedError("T-03306: loop_config_for")
