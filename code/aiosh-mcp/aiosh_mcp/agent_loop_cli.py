"""AI Control Plane Agent Loop Hardening CLI Surface (T-03285 scaffold / T-03286 impl / T-03289 sec / T-03290 hardening).

One-shot operator CLI over AgentLoopService (spec: docs/tasks/evidence/T-03284-spec.md):

    python -m aiosh_mcp.agent_loop_cli validate --plan plan.json
    python -m aiosh_mcp.agent_loop_cli run --loop-id ID --token-env AIOS_LOOP_GRANT --plan plan.json [--json]
    python -m aiosh_mcp.agent_loop_cli history --loop-id ID [--limit N] [--json]

Loop state is in-memory, so `run` drives start -> turns -> complete in one process;
`history` reads the durable audit ring. Enforces LOOPCLI-INV1..LOOPCLI-INV4.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from aiosh_mcp import audit_client
from aiosh_mcp.agent_loop_data_model import LoopConfig, LoopState, mask_secrets
from aiosh_mcp.agent_loop_config import loop_config_for
from aiosh_mcp.agent_loop_config import resolve as resolve_config
from aiosh_mcp.agent_loop_gate import HistoryReadError, PepCapabilityGate, read_loop_history
from aiosh_mcp.agent_loop_service import (
    AgentLoopService,
    AgentLoopServiceError,
    LOOPSERV_ERR_INVALID_INPUT,
    LOOPSERV_ERR_TIMEOUT,
    LOOPSERV_ERR_UNAUTHORIZED,
    MAX_ACTION_INTENT_CHARS,
    MAX_TOKENS_PER_TURN,
    TOOL_NAME_PATTERN,
)

EXIT_SUCCESS: int = 0
EXIT_FAILURE: int = 1
EXIT_USAGE: int = 2
EXIT_UNAUTHORIZED: int = 3
EXIT_TIMEOUT: int = 4
EXIT_INTERRUPTED: int = 130  # 128 + SIGINT, shell convention

MAX_PLAN_BYTES = 1024 * 1024
MAX_PLAN_TURNS = 100
MAX_HISTORY_LIMIT = 1000
DEFAULT_HISTORY_LIMIT = 100
MAX_TOKEN_CHARS = 256

LOOPCLI_ERR_USAGE = "LOOPCLI_ERR_USAGE"
LOOPCLI_ERR_PLAN = "LOOPCLI_ERR_PLAN"
LOOPCLI_ERR_AUDIT_READ = "LOOPCLI_ERR_AUDIT_READ"
LOOPCLI_ERR_INTERRUPTED = "LOOPCLI_ERR_INTERRUPTED"


_PLAN_KEYS = {"action_intent", "tool_name", "tool_args", "tokens_consumed", "policy_allowed"}
_EXIT_BY_CODE = {
    LOOPSERV_ERR_UNAUTHORIZED: EXIT_UNAUTHORIZED,
    LOOPSERV_ERR_TIMEOUT: EXIT_TIMEOUT,
    LOOPSERV_ERR_INVALID_INPUT: EXIT_USAGE,
    "LOOPDATA_ERR_BOUNDS_EXCEEDED": EXIT_USAGE,
}


@dataclass(frozen=True)
class PlanTurn:
    """One planned turn from a plan file."""

    action_intent: str
    tool_name: Optional[str] = None
    tool_args: Optional[Dict[str, Any]] = None
    tokens_consumed: int = 0
    policy_allowed: bool = True


@dataclass
class CliResult:
    """Standard CLI result (LOOPCLI-INV2): exit code plus the --json payload."""

    exit_code: int
    subcommand: str
    data: Optional[Dict[str, Any]] = None
    error_code: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"ok": self.exit_code == EXIT_SUCCESS, "exit_code": self.exit_code,
                               "subcommand": self.subcommand}
        if self.data is not None:
            out["data"] = self.data
        if self.error_code:
            out["error_code"] = self.error_code
        if self.error:
            out["error"] = mask_secrets(self.error)
        return out


class PlanError(ValueError):
    """Raised for an unreadable or invalid plan file (exit 2)."""


class _UsageError(Exception):
    pass


class _AuditReadError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    """argparse that raises instead of printing and calling sys.exit."""

    def error(self, message: str) -> None:  # type: ignore[override]
        raise _UsageError(message)


def _parse_turn(i: int, raw: Any) -> PlanTurn:
    if not isinstance(raw, dict):
        raise PlanError(f"turn {i}: must be an object")
    unknown = set(raw) - _PLAN_KEYS
    if unknown:
        raise PlanError(f"turn {i}: unknown keys {sorted(unknown)}")
    intent = raw.get("action_intent")
    if not isinstance(intent, str) or not intent or len(intent) > MAX_ACTION_INTENT_CHARS:
        raise PlanError(f"turn {i}: action_intent must be a non-empty string <= {MAX_ACTION_INTENT_CHARS} chars")
    tool = raw.get("tool_name")
    if tool is not None and (not isinstance(tool, str) or not TOOL_NAME_PATTERN.match(tool)):
        raise PlanError(f"turn {i}: tool_name must match [A-Za-z0-9_.-]{{1,128}}")
    args = raw.get("tool_args")
    if args is not None and not isinstance(args, dict):
        raise PlanError(f"turn {i}: tool_args must be an object")
    tokens = raw.get("tokens_consumed", 0)
    if isinstance(tokens, bool) or not isinstance(tokens, int) or not (0 <= tokens <= MAX_TOKENS_PER_TURN):
        raise PlanError(f"turn {i}: tokens_consumed must be an int in [0, {MAX_TOKENS_PER_TURN}]")
    allowed = raw.get("policy_allowed", True)
    if not isinstance(allowed, bool):
        raise PlanError(f"turn {i}: policy_allowed must be a boolean")
    return PlanTurn(intent, tool, args, tokens, allowed)


def load_plan(path: str) -> List[PlanTurn]:
    """Reads and validates a plan file (LOOPCLI-INV3: before any grant redemption)."""
    p = Path(path)
    try:
        if not p.is_file():
            raise PlanError(f"plan file not found: {path}")
        # Bounded read (T-03289): never trust a prior stat(), the file can grow in between.
        with p.open("rb") as fh:
            raw = fh.read(MAX_PLAN_BYTES + 1)
        if len(raw) > MAX_PLAN_BYTES:
            raise PlanError(f"plan file exceeds {MAX_PLAN_BYTES} bytes")
        doc = json.loads(raw.decode("utf-8"))
    except RecursionError as exc:
        raise PlanError("plan file is nested too deeply") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PlanError(f"cannot read plan file: {exc}") from exc
    if not isinstance(doc, dict) or set(doc) != {"turns"} or not isinstance(doc["turns"], list):
        raise PlanError('plan must be an object with exactly one key "turns" (a list)')
    if not (1 <= len(doc["turns"]) <= MAX_PLAN_TURNS):
        raise PlanError(f"plan must contain 1..{MAX_PLAN_TURNS} turns")
    return [_parse_turn(i, t) for i, t in enumerate(doc["turns"])]


def _build_parser() -> _Parser:
    parser = _Parser(prog="python -m aiosh_mcp.agent_loop_cli", add_help=False)
    sub = parser.add_subparsers(dest="subcommand", parser_class=_Parser)

    v = sub.add_parser("validate", add_help=False)
    v.add_argument("--plan", required=True)
    v.add_argument("--json", action="store_true")

    r = sub.add_parser("run", add_help=False)
    r.add_argument("--loop-id", required=True)
    # Prefer --token-env / --token-stdin: --token is visible in the process list and shell history.
    tok = r.add_mutually_exclusive_group(required=True)
    tok.add_argument("--token")
    tok.add_argument("--token-env", metavar="VAR")
    tok.add_argument("--token-stdin", action="store_true")
    r.add_argument("--plan", required=True)
    # Omitted budgets fall back to the configured defaults (T-03308, agent_loop_config).
    r.add_argument("--max-iterations", type=int, default=None)
    r.add_argument("--max-total-tokens", type=int, default=None)
    r.add_argument("--total-timeout-ms", type=float, default=None)
    r.add_argument("--consecutive-failure-limit", type=int, default=None)
    r.add_argument("--json", action="store_true")

    c = sub.add_parser("config", add_help=False)
    c.add_argument("--config", dest="config_file", default=None)
    c.add_argument("--json", action="store_true")

    h = sub.add_parser("history", add_help=False)
    h.add_argument("--loop-id", required=True)
    h.add_argument("--limit", type=int, default=DEFAULT_HISTORY_LIMIT)
    h.add_argument("--json", action="store_true")
    return parser


def _resolve_token(ns: argparse.Namespace) -> str:
    """Returns the grant id from --token, --token-env VAR or one line of stdin (T-03289)."""
    if ns.token_env:
        return os.environ.get(ns.token_env, "").strip()
    if ns.token_stdin:
        return sys.stdin.readline(MAX_TOKEN_CHARS + 1).strip()[:MAX_TOKEN_CHARS + 1]
    return (ns.token or "").strip()


def _cmd_run(ns: argparse.Namespace, service: AgentLoopService) -> CliResult:
    turns = load_plan(ns.plan)
    ns.token = _resolve_token(ns)
    if len(ns.token) > MAX_TOKEN_CHARS:
        raise _UsageError(f"capability token longer than {MAX_TOKEN_CHARS} chars")
    cfg = loop_config_for(
        ns.loop_id,
        resolve_config(),
        max_iterations=ns.max_iterations,
        max_total_tokens=ns.max_total_tokens,
        total_timeout_ms=ns.total_timeout_ms,
        consecutive_failure_limit=ns.consecutive_failure_limit,
    )
    service.start_loop(cfg, capability_token=ns.token)
    steps: List[Dict[str, Any]] = []
    try:
        for turn in turns:
            if service.get_snapshot(ns.loop_id).is_terminated:
                break
            step = service.advance_turn(
                ns.loop_id, turn.action_intent, tool_name=turn.tool_name, tool_args=turn.tool_args,
                tokens_consumed=turn.tokens_consumed, policy_allowed=turn.policy_allowed,
                capability_token=ns.token,
            )
            steps.append(step.to_dict())
        snap = service.get_snapshot(ns.loop_id)
        if not snap.is_terminated and snap.current_state == LoopState.OBSERVE:
            snap = service.complete_loop(ns.loop_id, capability_token=ns.token)
    except BaseException as exc:
        # Honest terminal row (T-03290): a started loop never ends silently in the audit ring.
        _abort_quietly(service, ns.loop_id, ns.token, f"cli run interrupted: {type(exc).__name__}")
        raise
    return CliResult(EXIT_SUCCESS, "run", data={
        "loop_id": ns.loop_id,
        "run_id": service.run_id(ns.loop_id),
        "final_state": snap.current_state.value,
        "terminal_reason": snap.terminal_reason,
        "turns": steps,
        "refused": sum(1 for s in steps if s["outcome"] == "refused"),
        "turns_skipped": len(turns) - len(steps),
    })


def _abort_quietly(service: AgentLoopService, loop_id: str, token: str, reason: str) -> None:
    try:
        if not service.get_snapshot(loop_id).is_terminated:
            service.abort_loop(loop_id, reason, capability_token=token)
    except Exception:
        pass  # the original failure is what gets reported


def _cmd_history(ns: argparse.Namespace, db_path: Optional[str]) -> CliResult:
    if not (1 <= ns.limit <= MAX_HISTORY_LIMIT):
        raise _UsageError(f"--limit must be in [1, {MAX_HISTORY_LIMIT}]")
    try:
        events = read_loop_history(db_path, ns.loop_id, ns.limit)
    except HistoryReadError as exc:
        raise _AuditReadError(str(exc)) from exc
    return CliResult(EXIT_SUCCESS, "history", data={"loop_id": ns.loop_id, "events": events})


def dispatch_cli(
    argv: List[str],
    service: Optional[AgentLoopService] = None,
    db_path: Optional[str] = None,
) -> CliResult:
    """Parses argv and runs one subcommand; never raises."""
    sub = argv[0] if argv and argv[0] in {"validate", "run", "history", "config"} else "unknown"
    try:
        if any("\0" in a for a in argv):
            raise _UsageError("argument contains prohibited NUL byte")
        ns = _build_parser().parse_args(argv)
        if ns.subcommand is None:
            raise _UsageError("expected a subcommand: validate | run | history | config")
        if ns.subcommand == "config":
            return CliResult(EXIT_SUCCESS, "config", data=resolve_config(arg_config=ns.config_file))
        if ns.subcommand == "validate":
            return CliResult(EXIT_SUCCESS, "validate", data={"turns": len(load_plan(ns.plan))})
        if ns.subcommand == "run":
            svc = service or AgentLoopService(gate=PepCapabilityGate(db_path))
            return _cmd_run(ns, svc)
        return _cmd_history(ns, db_path)
    except _UsageError as exc:
        return CliResult(EXIT_USAGE, sub, error_code=LOOPCLI_ERR_USAGE, error=str(exc))
    except _AuditReadError as exc:
        return CliResult(EXIT_FAILURE, sub, error_code=LOOPCLI_ERR_AUDIT_READ, error=str(exc))
    except KeyboardInterrupt:
        return CliResult(EXIT_INTERRUPTED, sub, error_code=LOOPCLI_ERR_INTERRUPTED,
                         error="interrupted; any started loop was aborted and audited")
    except PlanError as exc:
        return CliResult(EXIT_USAGE, sub, error_code=LOOPCLI_ERR_PLAN, error=str(exc))
    except AgentLoopServiceError as exc:
        return CliResult(_EXIT_BY_CODE.get(exc.code, EXIT_FAILURE), sub, error_code=exc.code, error=str(exc))
    except ValueError as exc:
        msg = str(exc)
        code = msg.split(":", 1)[0] if msg.startswith("LOOPDATA_ERR_") else LOOPCLI_ERR_USAGE
        return CliResult(_EXIT_BY_CODE.get(code, EXIT_USAGE), sub, error_code=code, error=msg)
    except Exception as exc:  # last resort: never a traceback on stdout
        return CliResult(EXIT_FAILURE, sub, error_code="LOOPCLI_ERR_INTERNAL", error=f"{type(exc).__name__}: {exc}")


def render(result: CliResult, json_mode: bool) -> str:
    """Formats a result for stdout (masked, LOOPCLI-INV4)."""
    if json_mode:
        return mask_secrets(json.dumps(result.to_dict(), sort_keys=True))
    if result.exit_code != EXIT_SUCCESS:
        return mask_secrets(f"error [{result.error_code}] (exit {result.exit_code}): {result.error}")
    d = result.data or {}
    if result.subcommand == "validate":
        return f"plan OK: {d['turns']} turn(s)"
    if result.subcommand == "config":
        lines = [f"{k:<36} {v!s:<12} ({d['source'].get(k, 'default')})" for k, v in d["config"].items()]
        lines.append(f"config file: {d['source'].get('_file', 'default')}")
        lines += [f"warning: {e}" for e in d["errors"]]
        return mask_secrets("\n".join(lines))
    if result.subcommand == "run":
        lines = [f"[{t['step_index']}] {t['outcome']:<7} {t['tool_name'] or '-'}"
                 + (f"  {t['error_message']}" if t.get("error_message") else "") for t in d["turns"]]
        lines.append(f"loop {d['loop_id']}: {d['final_state']} ({len(d['turns'])} turn(s), "
                     f"{d['refused']} refused, {d['turns_skipped']} skipped)")
        return mask_secrets("\n".join(lines))
    lines = [f"{e['id']:>6} {e['ts']} {e['tool']:<24} {e['outcome']}" for e in d["events"]]
    lines.append(f"{len(d['events'])} event(s) for {d['loop_id']}")
    return mask_secrets("\n".join(lines))


def main(argv: Optional[List[str]] = None) -> int:
    """Console entry point; returns the process exit code."""
    args = list(sys.argv[1:] if argv is None else argv)
    result = dispatch_cli(args)
    json_mode = "--json" in args
    stream = sys.stdout if result.exit_code == EXIT_SUCCESS or json_mode else sys.stderr
    try:
        print(render(result, json_mode), file=stream)
        stream.flush()
    except OSError:
        # Reader went away (e.g. `| head`): BrokenPipeError on POSIX, OSError(EINVAL) on
        # Windows. Keep the exit code and silence the interpreter's flush-at-exit error.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), stream.fileno())
        except (OSError, ValueError, AttributeError):
            pass
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
