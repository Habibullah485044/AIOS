"""Agent Loop Hardening configuration (T-03305 scaffold / T-03306 implementation).

Contract: ``docs/tasks/evidence/T-03304-spec.md`` (normative).
Research: ``docs/tasks/evidence/T-03303-research.md``.

Read-only: resolving configuration writes no files and no audit rows. Consumers
(service capacity, gate busy timeout, MCP bounds) are wired in T-03308.

Precedence (spec §3): argument -> per-field env -> config file -> default,
then clamp. Security and audit controls are locked and not representable
(AGENTLOOPCONF-INV2).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

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


_LOOP_FIELDS = {
    "max_iterations": "default_max_iterations",
    "max_total_tokens": "default_max_total_tokens",
    "timeout_ms_per_step": "default_timeout_ms_per_step",
    "total_timeout_ms": "default_total_timeout_ms",
    "consecutive_failure_limit": "default_consecutive_failure_limit",
}


class _ConfigError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def default_config() -> Dict[str, Any]:
    """Fresh dict of spec §2 defaults."""
    return {k: f.kind(f.default) for k, f in FIELDS.items()}


def hygiene_ok(value: Any) -> bool:
    """Total CWE-15 predicate for env-supplied paths; never raises."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    return (bool(v) and len(v) <= MAX_CONFIG_PATH_LEN and ".." not in v
            and not any(ord(ch) < 32 or ord(ch) == 127 for ch in v))


def _number(key: str, value: Any) -> float:
    """Parses a numeric setting; bools and non-numbers are rejected."""
    if isinstance(value, bool):
        raise ValueError(f"{key}: boolean is not a number")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        return float(value.strip())
    raise ValueError(f"{key}: expected a number, got {type(value).__name__}")


def _check_key(key: str) -> None:
    if key in LOCKED_KEYS:
        raise _ConfigError(AGENTLOOPCONF_ERR_LOCKED, f"{key!r} is a locked security control and cannot be configured")
    if key not in FIELDS:
        raise _ConfigError(AGENTLOOPCONF_ERR_UNKNOWN_KEY, f"unknown key {key!r}")


def _clamp(key: str, value: float, errors: List[str]) -> Any:
    f = FIELDS[key]
    clamped = min(max(value, f.lo), f.hi)
    if clamped != value:
        errors.append(f"{AGENTLOOPCONF_ERR_BOUNDS}: {key}={value:g} clamped to {clamped:g}")
    return f.kind(clamped)


def validate(config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge onto defaults and clamp; unknown/locked keys raise ValueError."""
    if config is not None and not isinstance(config, dict):
        raise ValueError(f"{AGENTLOOPCONF_ERR_PARSE}: config must be an object")
    merged = default_config()
    for key, value in (config or {}).items():
        try:
            _check_key(key)
        except _ConfigError as exc:
            raise ValueError(str(exc)) from exc
        merged[key] = _clamp(key, _number(key, value), [])
    return merged


def _read_file(path: str) -> Dict[str, float]:
    """Bounded read of a config file; raises _ConfigError on any defect (whole file rejected)."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_CONFIG_FILE_BYTES + 1)
    except OSError as exc:
        raise _ConfigError(AGENTLOOPCONF_ERR_IO, f"cannot read {path}: {exc}") from exc
    if len(raw) > MAX_CONFIG_FILE_BYTES:
        raise _ConfigError(AGENTLOOPCONF_ERR_FILE_SIZE, f"{path} exceeds {MAX_CONFIG_FILE_BYTES} bytes")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise _ConfigError(AGENTLOOPCONF_ERR_PARSE, f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise _ConfigError(AGENTLOOPCONF_ERR_PARSE, f"{path} must contain a JSON object")
    values: Dict[str, float] = {}
    for key, value in doc.items():
        _check_key(key)
        try:
            values[key] = _number(key, value)
        except ValueError as exc:
            raise _ConfigError(AGENTLOOPCONF_ERR_PARSE, str(exc)) from exc
    return values


def resolve(arg_config: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Full precedence ladder -> {"config", "source", "errors"}; never raises (AGENTLOOPCONF-INV1)."""
    errors: List[str] = []
    values: Dict[str, float] = {k: float(f.default) for k, f in FIELDS.items()}
    source: Dict[str, str] = {k: "default" for k in FIELDS}

    # Level 3: config file.
    path: Optional[str] = None
    source["_file"] = "default"
    if arg_config is not None:
        path = arg_config
    elif ENV_AGENT_LOOP_CONFIG in os.environ:
        env_path = os.environ[ENV_AGENT_LOOP_CONFIG]
        if hygiene_ok(env_path):
            path = env_path
        else:
            source["_file"] = "env_invalid"
            errors.append(f"{AGENTLOOPCONF_ERR_ENV}: {ENV_AGENT_LOOP_CONFIG} rejected by path hygiene")
    elif os.path.isfile(DEFAULT_CONFIG_PATH):
        path = DEFAULT_CONFIG_PATH
    if path is not None:
        try:
            for key, value in _read_file(path).items():
                values[key], source[key] = value, "file"
            source["_file"] = "file"
        except _ConfigError as exc:
            source["_file"] = "config_invalid"
            errors.append(str(exc))

    # Level 2: per-field env (a bad value is reported and not applied).
    for key, f in FIELDS.items():
        raw = os.environ.get(f.env)
        if raw is None:
            continue
        try:
            values[key], source[key] = _number(key, raw), "env"
        except ValueError:
            source[key] = "env_invalid"
            errors.append(f"{AGENTLOOPCONF_ERR_ENV}: {f.env} is not a number")

    # Level 1: explicit overrides (strongest).
    for key, value in (overrides or {}).items():
        try:
            _check_key(key)
            values[key], source[key] = _number(key, value), "argument"
        except (_ConfigError, ValueError) as exc:
            errors.append(str(exc))

    config = {key: _clamp(key, values[key], errors) for key in FIELDS}
    return {"config": config, "source": source, "errors": errors}


def loop_config_for(loop_id: str, resolved: Optional[Dict[str, Any]] = None, **explicit: Any) -> LoopConfig:
    """LoopConfig from resolved defaults plus explicit per-call values (explicit wins; None = use default)."""
    if resolved is None:
        resolved = resolve()
    cfg = resolved.get("config", resolved)
    kwargs = {field: cfg[key] for field, key in _LOOP_FIELDS.items()}
    for field, value in explicit.items():
        if field not in _LOOP_FIELDS:
            raise TypeError(f"unknown LoopConfig field {field!r}")
        if value is not None:
            kwargs[field] = value
    return LoopConfig(loop_id=loop_id, **kwargs)
