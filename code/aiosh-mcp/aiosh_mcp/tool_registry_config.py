"""Tool Registry & Taxonomy configuration (T-03405 scaffold / T-03406 impl).

Spec: docs/tasks/evidence/T-03404-spec.md. Three tunables (mode, report_max_lines, unregistered_samples)
from argument / env / config file / default. The mode is strictest-wins; security policy is locked and not
representable (TOOLREGCONF-INV1..TOOLREGCONF-INV4). Resolving never raises, writes nothing, audits nothing.
"""

from __future__ import annotations

import json
import os
import stat
import threading
import unicodedata
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

TOOLREGCONF_ERR_IO = "TOOLREGCONF_ERR_IO"
TOOLREGCONF_ERR_FILE_SIZE = "TOOLREGCONF_ERR_FILE_SIZE"
TOOLREGCONF_ERR_PARSE = "TOOLREGCONF_ERR_PARSE"
TOOLREGCONF_ERR_UNKNOWN_KEY = "TOOLREGCONF_ERR_UNKNOWN_KEY"
TOOLREGCONF_ERR_LOCKED = "TOOLREGCONF_ERR_LOCKED"
TOOLREGCONF_ERR_BOUNDS = "TOOLREGCONF_ERR_BOUNDS"
TOOLREGCONF_ERR_ENV = "TOOLREGCONF_ERR_ENV"

ENV_CONFIG = "AIOSH_TOOL_REGISTRY_CONFIG"
#: Default file name under $AIOSH_HOME (T-03409 #5: never relative to the server's working directory).
DEFAULT_CONFIG_NAME = "tool_registry_config.json"


def default_config_path() -> str:
    from aiosh_mcp import audit_client
    return os.path.join(os.path.dirname(os.path.abspath(audit_client.default_db_path())), DEFAULT_CONFIG_NAME)
MAX_CONFIG_FILE_BYTES = 64 * 1024
MAX_CONFIG_PATH_LEN = 1024
MODES = ("shadow", "strict")
MAX_ERROR_CHARS = 300


@dataclass(frozen=True)
class IntField:
    default: int
    lo: int
    hi: int
    env: str


#: Numeric tunables (spec §1). ``mode`` is handled separately (strictest wins).
FIELDS: Dict[str, IntField] = {
    "report_max_lines": IntField(32, 1, 1000, "AIOSH_TOOL_REGISTRY_REPORT_MAX_LINES"),   # >= 1 (T-03409 #6)
    "unregistered_samples": IntField(50, 0, 200, "AIOSH_TOOL_REGISTRY_UNREGISTERED_SAMPLES"),
}
ENV_MODE = "AIOSH_TOOL_REGISTRY_MODE"
#: Security policy: not representable in configuration (TOOLREGCONF-INV2).
LOCKED_KEYS: Tuple[str, ...] = ("catalog", "entries", "read_only_hint_categories", "grant_params", "path_params",
                                "irreversible_names", "irreversible_prefixes")


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """Duplicate keys are ambiguous (a reviewer sees the first, json keeps the last): reject (T-03409 #7)."""
    out: Dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key {str(key)[:40]!r}")
        out[key] = value
    return out


class _ConfigError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


def _err(code: str, message: str) -> str:
    return f"{code}: {message}"[:MAX_ERROR_CHARS]


def _mode_value(raw: Any) -> Optional[str]:
    """``shadow`` / ``strict``; an unrecognised non-empty value counts as strict (fail closed); empty = None."""
    if not isinstance(raw, str):
        return "strict"
    value = unicodedata.normalize("NFKC", raw).strip().lower()
    if not value:
        return None
    return value if value in MODES else "strict"


def _read_file(path: str) -> Dict[str, Any]:
    """Bounded read of a regular file holding a JSON object; raises _ConfigError (whole file rejected)."""
    from aiosh_mcp.agent_loop_config import _special_path_reason
    name = os.path.basename(path.replace("\\", "/").rstrip("/")) or "config"
    reason = _special_path_reason(path)
    if reason:
        raise _ConfigError(TOOLREGCONF_ERR_IO, f"cannot read {name}: {reason}")
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            raise _ConfigError(TOOLREGCONF_ERR_IO, f"cannot read {name}: not a regular file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise _ConfigError(TOOLREGCONF_ERR_IO, f"cannot read {name}: not a regular file")
            raw = os.read(fd, MAX_CONFIG_FILE_BYTES + 1)
        finally:
            os.close(fd)
    except OSError as exc:
        raise _ConfigError(TOOLREGCONF_ERR_IO, f"cannot read {name}: {exc.strerror or 'I/O error'}") from exc
    if len(raw) > MAX_CONFIG_FILE_BYTES:
        raise _ConfigError(TOOLREGCONF_ERR_FILE_SIZE, f"{name} exceeds {MAX_CONFIG_FILE_BYTES} bytes")
    try:
        doc = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_no_duplicates)   # BOM ok (T-03409 #2)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _ConfigError(TOOLREGCONF_ERR_PARSE, f"{name} is not valid JSON ({type(exc).__name__})") from exc
    if not isinstance(doc, dict):
        raise _ConfigError(TOOLREGCONF_ERR_PARSE, f"{name} must contain a JSON object")
    for key, value in doc.items():
        if key in LOCKED_KEYS:
            raise _ConfigError(TOOLREGCONF_ERR_LOCKED, f"{key!r} is security policy and cannot be configured")
        if key != "mode" and key not in FIELDS:
            raise _ConfigError(TOOLREGCONF_ERR_UNKNOWN_KEY, f"unknown key {str(key)[:40]!r}")
        if key == "mode" and not isinstance(value, str):
            raise _ConfigError(TOOLREGCONF_ERR_PARSE, "mode must be a string")
        if key in FIELDS and (isinstance(value, bool) or not isinstance(value, int)):
            raise _ConfigError(TOOLREGCONF_ERR_PARSE, f"{key} must be an integer")
    return doc


#: Placed in the file values when a configured file could not be used: an unreadable or rejected file
#: may have been asking for strict, so it counts as strict (T-03409 #2, #3). It never loosens anything.
_UNTRUSTED_FILE = {"mode": "strict"}


def _file(errors: List[str]) -> Tuple[Dict[str, Any], Optional[str]]:
    from aiosh_mcp.agent_loop_config import hygiene_ok
    path: Optional[str] = None
    env_path = os.environ.get(ENV_CONFIG, "")
    if env_path.strip():
        if not hygiene_ok(env_path):
            errors.append(_err(TOOLREGCONF_ERR_IO, f"{ENV_CONFIG} rejected by path hygiene; mode strict"))
            return dict(_UNTRUSTED_FILE), None
        path = env_path.strip()
    else:
        try:
            candidate = default_config_path()
            exists = os.path.isfile(candidate)
        except (OSError, ValueError) as exc:  # T-03410: isolate; env values still apply
            errors.append(_err(TOOLREGCONF_ERR_IO, f"default config location unavailable ({type(exc).__name__}); "
                                                   f"mode strict"))
            return dict(_UNTRUSTED_FILE), None
        if exists:
            path = candidate
    if path is None:
        return {}, None
    try:
        return _read_file(path), path
    except _ConfigError as exc:
        errors.append(_err(exc.code, str(exc).split(": ", 1)[1] + "; file ignored, mode strict"))
        return dict(_UNTRUSTED_FILE), path      # numbers: defaults; mode: fail closed


def resolve(arg_mode: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Resolved configuration with sources and errors (spec §3). Never raises (TOOLREGCONF-INV3)."""
    try:
        return _resolve(arg_mode, overrides)
    except Exception as exc:  # defensive: configuration must never break the registry
        return {"config": {"mode": "strict", **{k: f.default for k, f in FIELDS.items()}},   # fail closed (#8)
                "sources": {}, "errors": [_err(TOOLREGCONF_ERR_IO, f"resolution failed ({type(exc).__name__})")],
                "path": None}


def _resolve(arg_mode: Optional[str], overrides: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    errors: List[str] = []
    file_values, path = _file(errors)
    overrides = overrides or {}
    config: Dict[str, Any] = {}
    sources: Dict[str, str] = {}
    for key, field in FIELDS.items():
        value, source = field.default, "default"
        if key in file_values:
            value, source = file_values[key], "file"
        raw_env = os.environ.get(field.env)
        if raw_env is not None and raw_env.strip():
            try:
                value, source = int(raw_env.strip()), "env"
            except ValueError:
                errors.append(_err(TOOLREGCONF_ERR_ENV, f"{field.env} is not an integer; ignored"))
        if key in overrides and isinstance(overrides[key], int) and not isinstance(overrides[key], bool):
            value, source = overrides[key], "argument"
        if not field.lo <= value <= field.hi:
            errors.append(_err(TOOLREGCONF_ERR_BOUNDS, f"{key}={value} clamped to [{field.lo}, {field.hi}]"))
            value = min(field.hi, max(field.lo, value))
        config[key], sources[key] = value, source
    # Mode: strictest wins across every source (TOOLREGCONF-INV1).
    asked = [("argument", arg_mode), ("env", os.environ.get(ENV_MODE)), ("file", file_values.get("mode"))]
    strict_from = [src for src, raw in asked if raw is not None and _mode_value(raw) == "strict"]
    config["mode"] = "strict" if strict_from else "shadow"
    sources["mode"] = "+".join(strict_from) if strict_from else next(
        (src for src, raw in asked if raw is not None and _mode_value(raw) == "shadow"), "default")
    return {"config": config, "sources": sources, "errors": errors, "path": path}


_PROCESS: Optional[Dict[str, Any]] = None
_LOCK = threading.Lock()


def _announce(resolved: Dict[str, Any]) -> None:
    """Configuration problems are told to the operator once, on stderr (never stdout, never an audit row).

    T-03410: a rejected file silently forcing strict mode would look like unexplained refusals.
    """
    import sys
    stream = sys.stderr
    if not resolved["errors"] or stream is None or stream is sys.stdout:
        return
    try:
        mode = resolved["config"]["mode"]
        print(f"aiosh-mcp: tool registry config: {len(resolved['errors'])} problem(s); mode={mode}", file=stream)
        for error in resolved["errors"][:10]:
            print(f"aiosh-mcp:   {error!r}"[:MAX_ERROR_CHARS + 40], file=stream)
        stream.flush()
    except (OSError, ValueError):
        pass


def process_config() -> Dict[str, Any]:
    """Resolved once per process; problems are reported once on stderr."""
    global _PROCESS
    if _PROCESS is None:
        with _LOCK:
            if _PROCESS is None:
                _PROCESS = resolve()
                _announce(_PROCESS)
    return _PROCESS


def reset_process_config() -> None:
    """For tests: forget the per-process resolution."""
    global _PROCESS
    with _LOCK:
        _PROCESS = None
