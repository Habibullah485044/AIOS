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
import math
import os
import re
import stat
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

#: ``source`` values. Since T-03309 a key's source is always where its value really came from;
#: rejected inputs are listed in ``rejected`` / ``errors`` instead of overwriting the label.
CONFIG_SOURCES = ("argument", "env", "file", "default", "settings", "env_invalid", "config_invalid")
#: Longest error message kept (an echoed bad value must not flood the config tool).
MAX_ERROR_CHARS = 300
#: Windows device names: opening them blocks or touches hardware (T-03309).
_WIN_DEVICE = re.compile(r"^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[0-9]|LPT[0-9])(\..*)?$", re.IGNORECASE)


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
            and not any(ord(ch) < 32 or ord(ch) == 127 for ch in v)
            and _special_path_reason(v) is None)


def _special_path_reason(path: str) -> Optional[str]:
    """Why ``path`` must not be opened at all, or None (T-03309: hangs, device I/O, SMB/NTLM leaks)."""
    norm = path.replace("\\", "/")
    # "//" covers \\server\share and \\?\ / \\.\; "/??/" is the NT object-manager prefix (\??\UNC\host\...,
    # \??\C:\...), which Windows opens like the device namespace (T-03409 #1: SMB / NTLM leak).
    if norm.startswith("//") or norm.startswith("/??/") or norm.startswith("??/"):
        return "UNC / device namespace paths are not allowed"
    # Windows ignores trailing spaces, dots and a colon on device names ("CON .json", "nul:") (T-03409 #10).
    base = os.path.basename(norm.rstrip("/"))
    if _WIN_DEVICE.match(base) or _WIN_DEVICE.match(base.split(".")[0].rstrip(" :")) or \
            _WIN_DEVICE.match(base.rstrip(" .:")):
        return "Windows device names are not allowed"
    try:  # a link or junction whose target is a network path is refused too
        real = os.path.realpath(path)
    except (OSError, ValueError):
        return None
    if real.replace("\\", "/").startswith(("//", "/??/")):
        return "path resolves to a network or device location"
    return None


def _number(key: str, value: Any) -> float:
    """Parses a numeric setting; bools and non-numbers are rejected."""
    if isinstance(value, bool):
        raise ValueError(f"{key}: boolean is not a number")
    if isinstance(value, (int, float)):
        try:
            number = float(value)
        except OverflowError:  # e.g. a 400-digit JSON integer (T-03309)
            raise ValueError(f"{key}: number out of range") from None
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except (ValueError, OverflowError):
            raise ValueError(f"{key}: value is not a number") from None
    else:
        raise ValueError(f"{key}: expected a number, got {type(value).__name__}")
    # nan/inf slip past min()/max() clamping (security audit 2026-11-05 #7).
    if not math.isfinite(number):
        raise ValueError(f"{key}: value is not a finite number")
    return number


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
    """Bounded read of a config file; raises _ConfigError on any defect (whole file rejected).

    Only regular files are read, and the open never blocks (T-03309): a FIFO, a device such
    as CON or /dev/stdin, or a UNC path used to hang or crash the server at import.
    """
    name = os.path.basename(path.replace("\\", "/").rstrip("/")) or "config"
    reason = _special_path_reason(path)
    if reason:
        raise _ConfigError(AGENTLOOPCONF_ERR_IO, f"cannot read {name}: {reason}")
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            raise _ConfigError(AGENTLOOPCONF_ERR_IO, f"cannot read {name}: not a regular file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):  # swapped after the stat()
                raise _ConfigError(AGENTLOOPCONF_ERR_IO, f"cannot read {name}: not a regular file")
            raw = os.read(fd, MAX_CONFIG_FILE_BYTES + 1)
        finally:
            os.close(fd)
    except OSError as exc:
        raise _ConfigError(AGENTLOOPCONF_ERR_IO, f"cannot read {name}: {exc.strerror or 'I/O error'}") from exc
    if len(raw) > MAX_CONFIG_FILE_BYTES:
        raise _ConfigError(AGENTLOOPCONF_ERR_FILE_SIZE, f"{name} exceeds {MAX_CONFIG_FILE_BYTES} bytes")
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:  # ValueError covers >4300-digit ints
        raise _ConfigError(AGENTLOOPCONF_ERR_PARSE, f"{name} is not valid JSON ({type(exc).__name__})") from exc
    if not isinstance(doc, dict):
        raise _ConfigError(AGENTLOOPCONF_ERR_PARSE, f"{name} must contain a JSON object")
    values: Dict[str, float] = {}
    for key, value in doc.items():
        _check_key(key)
        try:
            values[key] = _number(key, value)
        except ValueError as exc:
            raise _ConfigError(AGENTLOOPCONF_ERR_PARSE, str(exc)) from exc
    return values


def resolve(arg_config: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Full precedence ladder -> {"config", "source", "rejected", "errors"}; never raises (AGENTLOOPCONF-INV1).

    The MCP server calls this at import, so any unexpected failure falls back to defaults.
    """
    try:
        out = _resolve(arg_config, overrides)
    except Exception as exc:  # last line of defence for AGENTLOOPCONF-INV1
        out = {"config": default_config(), "source": {**{k: "default" for k in FIELDS}, "_file": "config_invalid"},
               "rejected": {}, "errors": [f"{AGENTLOOPCONF_ERR_PARSE}: configuration ignored ({type(exc).__name__})"]}
    from aiosh_mcp.agent_loop_data_model import mask_secrets
    out["errors"] = [mask_secrets(e)[:MAX_ERROR_CHARS] for e in out["errors"]]
    return out


def _resolve(arg_config: Optional[str], overrides: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    errors: List[str] = []
    rejected: Dict[str, str] = {}
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
            rejected[key] = "env_invalid"  # source keeps the level actually in effect
            errors.append(f"{AGENTLOOPCONF_ERR_ENV}: {f.env} is not a finite number")

    # Level 1: explicit overrides (strongest).
    for key, value in (overrides or {}).items():
        try:
            _check_key(key)
            values[key], source[key] = _number(key, value), "argument"
        except (_ConfigError, ValueError) as exc:
            if key in FIELDS:
                rejected[key] = "argument_invalid"
            errors.append(str(exc))

    config = {key: _clamp(key, values[key], errors) for key in FIELDS}
    # A DB lock wait longer than the MCP call bound guarantees "outcome unknown" results:
    # keep the busy wait under half the call timeout (T-03309).
    cap = max(int(FIELDS["db_busy_timeout_ms"].lo), int(config["mcp_call_timeout_s"] * 1000 // 2))
    if config["db_busy_timeout_ms"] > cap:
        errors.append(f"{AGENTLOOPCONF_ERR_BOUNDS}: db_busy_timeout_ms={config['db_busy_timeout_ms']} lowered to "
                      f"{cap} (must stay under half of mcp_call_timeout_s)")
        config["db_busy_timeout_ms"] = cap
    return {"config": config, "source": source, "rejected": rejected, "errors": errors}


_PROCESS_CONFIG: Optional[Dict[str, Any]] = None


def process_config() -> Dict[str, Any]:
    """The configuration this process runs with, resolved once (T-03310).

    Service capacity, gate busy timeout and the MCP tools all read this, so the
    ``aios_agent_loop_config`` tool reports exactly what is in effect.
    """
    global _PROCESS_CONFIG
    if _PROCESS_CONFIG is None:
        _PROCESS_CONFIG = resolve()
    return _PROCESS_CONFIG


def reset_process_config() -> None:
    """Forget the cached resolution (tests / explicit operator reload)."""
    global _PROCESS_CONFIG
    _PROCESS_CONFIG = None


def audit_degraded(resolved: Dict[str, Any], db_path: Optional[str] = None) -> Optional[str]:
    """Writes one ``aios.agent_loop.config`` audit row when inputs were rejected (T-03310).

    Falling back to defaults is a fail-open, so ADR-0035 §F-2 requires an honest audit row.
    Returns None on success or when there is nothing to report, else the reason the row
    could not be written (callers surface it; this never raises).
    """
    if not resolved.get("errors"):
        return None
    try:
        from contextlib import closing
        from aiosh_mcp import audit_client
        with closing(audit_client.open_db(db_path)) as conn:
            audit_client.write_audit_row(conn, {
                "ts": audit_client.utcnow_iso(),
                "actor": "agent",
                "actor_id": "agent:mcp@aiosh-mcp/agent-loop",
                "tool": "aios.agent_loop.config",
                "command": "agent_loop.config resolve",
                "args": {"rejected": resolved.get("rejected", {}), "file": resolved["source"].get("_file"),
                         "errors": resolved["errors"][:20]},
                "target": None,
                "outcome": "degraded",
                "outcome_detail": f"{len(resolved['errors'])} configuration input(s) rejected or adjusted",
                "constitution_rev": None,
                "grant_token": None,
                "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True},
            })
        return None
    except Exception as exc:
        return f"{AGENTLOOPCONF_ERR_IO}: could not audit degraded configuration ({type(exc).__name__})"


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
