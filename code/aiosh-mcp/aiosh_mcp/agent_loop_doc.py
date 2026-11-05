"""Agent Loop Hardening generated reference documentation (T-03345 scaffold).

Spec: docs/tasks/evidence/T-03344-spec.md. The reference is derived from code at call
time (LOOPDOC-INV2); the only hand-written table is ``ERROR_MEANINGS``, whose
completeness is enforced by tests in both directions.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

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


def reference(section: Optional[str] = None) -> Dict[str, Any]:
    """Code-generated reference: one section, or all of ``SECTIONS``."""
    raise NotImplementedError("T-03346: reference")
