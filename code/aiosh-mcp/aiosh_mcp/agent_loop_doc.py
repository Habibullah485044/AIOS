"""Agent Loop Hardening generated reference documentation (T-03345 scaffold / T-03346 impl).

Spec: docs/tasks/evidence/T-03344-spec.md. The reference is derived from code at call
time (LOOPDOC-INV2); the only hand-written table is ``ERROR_MEANINGS``, whose
completeness is enforced by tests in both directions.
"""

from __future__ import annotations

import importlib
from typing import Any, Dict, List, Optional

SECTIONS = ("tools", "errors", "config", "cli", "policy")

#: One line per error code; tests assert every *_ERR_* constant has an entry and vice versa.
ERROR_MEANINGS: Dict[str, str] = {
    "LOOPDATA_ERR_BOUNDS_EXCEEDED": "LoopConfig value out of range, or loop_id not ^[a-zA-Z0-9_-]{8,64}$",
    "LOOPDATA_ERR_INVALID_STATE": "data-model registry: loop already exists / invalid state for the operation",
    "LOOPDATA_ERR_INVALID_TRANSITION": "FSM transition not allowed by the transition table",
    "LOOPDATA_ERR_INVARIANT_VIOLATION": "snapshot invariant broken (step indices, token conservation)",
    "LOOPDATA_ERR_NOT_FOUND": "data-model status: unknown loop id",
    "LOOPDATA_ERR_UNAUTHORIZED": "data-model init: missing or unredeemable capability token",
    "LOOPSERV_ERR_NOT_FOUND": "unknown loop id",
    "LOOPSERV_ERR_ALREADY_EXISTS": "loop id already started (loop ids are single-use per audit ring)",
    "LOOPSERV_ERR_TERMINATED": "loop is COMPLETED/FAILED/ABORTED",
    "LOOPSERV_ERR_UNAUTHORIZED": "missing, forged, replayed, out-of-scope, revoked or wrong-loop capability token",
    "LOOPSERV_ERR_POLICY_REFUSED": "step refused by P1..P4 (in step.error_message; the call itself succeeds)",
    "LOOPSERV_ERR_TIMEOUT": "total_timeout_ms exceeded; loop ABORTED",
    "LOOPSERV_ERR_CIRCUIT_BREAKER": "loop terminated by a breaker (consecutive failures, token budget, iteration ceiling); prefix of terminal_reason",
    "LOOPSERV_ERR_INVALID_INPUT": "input caps: action_intent/reason length, tool_name pattern, tokens, tool_args size/depth/no-tool",
    "LOOPSERV_ERR_CAPACITY": "registry full and no terminated loop to evict",
    "LOOPSERV_ERR_AUDIT": "audit write failed; loop not created (start) or ABORTED",
    "LOOPSERV_ERR_GATE_UNAVAILABLE": "grant DB unreachable; fails closed",
    "LOOPPOL_ERR_CONSTITUTION": "P2: constitution classifier refused the step",
    "LOOPPOL_ERR_IRREVERSIBLE_BUDGET": "P4: grant's max_irreversible budget spent",
    "LOOPPOL_ERR_TARGET": "non-string value under a target-like tool_args key",
    "LOOPMCP_ERR_AUDIT_READ": "history: audit DB corrupt or unreadable",
    "LOOPMCP_ERR_TIMEOUT": "MCP call exceeded its bound; for mutating tools the outcome is unknown",
    "LOOPOBS_ERR_READ": "metrics: audit DB unreadable or query exceeded its time budget",
    "LOOPCLI_ERR_USAGE": "CLI usage error (exit 2)",
    "LOOPCLI_ERR_PLAN": "CLI plan file invalid (exit 2)",
    "LOOPCLI_ERR_AUDIT_READ": "CLI history/metrics: audit DB unreadable (exit 1)",
    "LOOPCLI_ERR_INTERRUPTED": "CLI run interrupted; started loop aborted and audited (exit 130)",
    "AGENTLOOPCONF_ERR_FILE_SIZE": "config file larger than 64 KiB; ignored",
    "AGENTLOOPCONF_ERR_IO": "config file unreadable, missing, special file or UNC/device path; ignored",
    "AGENTLOOPCONF_ERR_PARSE": "config file not a JSON object of finite numbers; ignored",
    "AGENTLOOPCONF_ERR_UNKNOWN_KEY": "config key not a known tunable; whole file ignored",
    "AGENTLOOPCONF_ERR_LOCKED": "config tried to set a locked security control; whole file ignored",
    "AGENTLOOPCONF_ERR_BOUNDS": "config value clamped to its bounds (reported, applied clamped)",
    "AGENTLOOPCONF_ERR_ENV": "env value or env config path rejected; lower level kept",
}


#: Modules whose ``*_ERR_*`` constants make up the error catalog.
_MODULES = ("agent_loop_data_model", "agent_loop_service", "agent_loop_gate", "agent_loop_policy",
            "agent_loop_mcp", "agent_loop_cli", "agent_loop_config", "agent_loop_observability")


def _tools() -> List[Dict[str, Any]]:
    from mcp.server.fastmcp import FastMCP
    from aiosh_mcp.agent_loop_data_model import register_agent_loop_data_model_tools
    from aiosh_mcp.agent_loop_mcp import register_agent_loop_mcp_tools
    app = FastMCP("agent-loop-reference")
    register_agent_loop_mcp_tools(app, settings={})   # settings={}: no config resolution or audit side effects
    register_agent_loop_data_model_tools(app)         # the legacy init/status tools are served too (T-03348)
    out = []
    for t in sorted(app._tool_manager.list_tools(), key=lambda t: t.name):
        ann = t.annotations.model_dump(exclude_none=True) if t.annotations else {}
        out.append({"name": t.name, "description": (t.description or "").strip().splitlines()[0],
                    "annotations": ann, "input_schema": t.parameters})
    return out


def _errors() -> List[Dict[str, str]]:
    found: Dict[str, str] = {}
    for name in _MODULES:
        mod = importlib.import_module(f"aiosh_mcp.{name}")
        for attr, value in vars(mod).items():
            if "_ERR_" in attr and attr.isupper() and isinstance(value, str) and value == attr:
                found.setdefault(attr, name)   # first definer wins (re-exports are skipped)
    return [{"code": c, "module": m, "meaning": ERROR_MEANINGS.get(c, "")} for c, m in sorted(found.items())]


def _config() -> Dict[str, Any]:
    from aiosh_mcp import agent_loop_config as cfg
    fields = [{"key": k, "default": f.kind(f.default), "min": f.kind(f.lo), "max": f.kind(f.hi),
               "type": f.kind.__name__, "env": f.env} for k, f in cfg.FIELDS.items()]
    return {"fields": fields, "locked_keys": list(cfg.LOCKED_KEYS), "file_env": cfg.ENV_AGENT_LOOP_CONFIG,
            "default_file": cfg.DEFAULT_CONFIG_PATH, "max_file_bytes": cfg.MAX_CONFIG_FILE_BYTES}


def _cli() -> List[Dict[str, Any]]:
    import argparse
    from aiosh_mcp.agent_loop_cli import _build_parser
    parser = _build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    out = []
    for name, sp in sub.choices.items():
        flags = [o for a in sp._actions for o in a.option_strings]
        out.append({"subcommand": name, "flags": sorted(flags)})
    return out


def _policy() -> Dict[str, Any]:
    from aiosh_mcp import agent_loop_policy as pol
    from aiosh_mcp.classifier import CLASSIFIER_REVISION
    return {"order": ["P1 caller verdict", "P2 constitution classifier", "P3 grant scope", "P4 irreversible budget"],
            "classifier_revision": CLASSIFIER_REVISION,
            "irreversible_prefixes": list(pol.IRREVERSIBLE_PREFIXES), "irreversible_tools": list(pol.IRREVERSIBLE_TOOLS),
            "target_arg_keys": list(pol.TARGET_ARG_KEYS)}


_BUILDERS = {"tools": _tools, "errors": _errors, "config": _config, "cli": _cli, "policy": _policy}


def reference(section: Optional[str] = None) -> Dict[str, Any]:
    """Code-generated reference: one section, or all of ``SECTIONS`` (LOOPDOC-INV2)."""
    if section is None:
        return {name: _BUILDERS[name]() for name in SECTIONS}
    if section not in _BUILDERS:
        raise ValueError(f"unknown section {section!r}; expected one of {', '.join(SECTIONS)}")
    return {section: _BUILDERS[section]()}
