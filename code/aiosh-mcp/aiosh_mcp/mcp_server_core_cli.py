"""AI Control Plane MCP Server Core CLI Surface (T-03085).

Exposes command line operations for MCP tool inspection, session management,
and bounded dispatch in compliance with ADR-0035 §AF-2 and PoR Invariant I-2.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .mcp_server_core_data_model import (
    McpToolCall,
    MAX_ARGUMENTS_SIZE,
    ERR_UNAUTHORIZED,
)
from .mcp_server_core_service import (
    McpServerCoreService,
    DEFAULT_EXECUTION_TIMEOUT_SECONDS,
    MCPSVC_ERR_TOOL_NOT_FOUND,
)

EXIT_SUCCESS: int = 0
EXIT_FAILURE: int = 1
EXIT_USAGE: int = 2
EXIT_UNAUTHORIZED: int = 3
EXIT_TIMEOUT: int = 4


@dataclass
class McpCliOutput:
    exit_code: int
    message: str
    json_payload: Optional[Dict[str, Any]] = None

    @classmethod
    def success(cls, message: str, payload: Optional[Dict[str, Any]] = None) -> "McpCliOutput":
        return cls(exit_code=EXIT_SUCCESS, message=message, json_payload=payload)

    @classmethod
    def failure(cls, exit_code: int, message: str) -> "McpCliOutput":
        return cls(exit_code=exit_code, message=message, json_payload=None)

    @classmethod
    def failure_with_json(cls, exit_code: int, message: str, json_mode: bool = False) -> "McpCliOutput":
        if json_mode:
            payload = {
                "status": "error",
                "ok": False,
                "error_code": exit_code,
                "error_message": message,
            }
            return cls(exit_code=exit_code, message=json.dumps(payload), json_payload=payload)
        return cls(exit_code=exit_code, message=message, json_payload=None)


def parse_mcp_cli_args(args: List[str]) -> Tuple[str, Dict[str, Any]]:
    if not args:
        raise ValueError("Missing MCP subcommand (choose from list, show, dispatch, sessions, ping)")

    for arg in args:
        if "\0" in arg:
            raise ValueError("CLI argument contains prohibited NUL byte")

    subcmd = args[0]
    options: Dict[str, Any] = {
        "json": False,
        "filter": None,
        "args": None,
        "grant": None,
        "timeout": None,
        "prune": None,
        "positional": [],
    }

    i = 1
    while i < len(args):
        flag = args[i]
        if flag == "--json":
            options["json"] = True
        elif flag == "--filter":
            i += 1
            if i >= len(args):
                raise ValueError("--filter requires a value")
            options["filter"] = args[i]
        elif flag == "--args":
            i += 1
            if i >= len(args):
                raise ValueError("--args requires a JSON value")
            options["args"] = args[i]
        elif flag == "--grant":
            i += 1
            if i >= len(args):
                raise ValueError("--grant requires a grant token")
            options["grant"] = args[i]
        elif flag == "--timeout":
            i += 1
            if i >= len(args):
                raise ValueError("--timeout requires seconds")
            options["timeout"] = int(args[i])
        elif flag == "--prune":
            i += 1
            if i < len(args) and not args[i].startswith("--"):
                options["prune"] = float(args[i])
            else:
                options["prune"] = 0.0
                continue
        elif flag.startswith("--"):
            raise ValueError(f"unknown flag '{flag}'")
        else:
            options["positional"].append(flag)
        i += 1

    return subcmd, options


def execute_mcp_cli(subcmd: str, options: Dict[str, Any], service: McpServerCoreService) -> McpCliOutput:
    json_mode = options.get("json", False)

    if subcmd == "ping":
        tools_count = len(service.list_tools())
        payload = {
            "status": "ok",
            "tools_count": tools_count,
            "version": "2025-06-18",
        }
        msg = json.dumps(payload) if json_mode else f"MCP Server Core is alive ({tools_count} registered tools)"
        return McpCliOutput.success(msg, payload)

    elif subcmd == "list":
        tools = service.list_tools()
        filter_str = options.get("filter")
        if filter_str:
            tools = [t for t in tools if filter_str in t.name]
        tools_dicts = [t.to_dict() for t in tools]
        msg = json.dumps(tools_dicts) if json_mode else "\n".join(f"{t.name}: {t.description}" for t in tools)
        return McpCliOutput.success(msg, {"tools": tools_dicts})

    elif subcmd == "show":
        pos = options.get("positional", [])
        if not pos:
            return McpCliOutput.failure_with_json(EXIT_USAGE, "show requires a tool name", json_mode=json_mode)
        tool_name = pos[0]
        tool = service.get_tool(tool_name)
        if not tool:
            return McpCliOutput.failure_with_json(EXIT_FAILURE, f"tool '{tool_name}' not found", json_mode=json_mode)
        tool_dict = tool.to_dict()
        msg = json.dumps(tool_dict) if json_mode else f"Tool: {tool.name}\nDescription: {tool.description}"
        return McpCliOutput.success(msg, tool_dict)

    elif subcmd == "dispatch":
        pos = options.get("positional", [])
        if not pos:
            return McpCliOutput.failure_with_json(EXIT_USAGE, "dispatch requires a tool name", json_mode=json_mode)
        tool_name = pos[0]
        grant = options.get("grant")

        if tool_name.startswith("aios.admin.") and not grant:
            return McpCliOutput.failure_with_json(EXIT_UNAUTHORIZED, "capability grant required for privileged tool", json_mode=json_mode)

        raw_args = options.get("args")
        if raw_args:
            if len(raw_args) > MAX_ARGUMENTS_SIZE:
                return McpCliOutput.failure_with_json(EXIT_USAGE, "arguments exceed MAX_ARGUMENTS_SIZE limit", json_mode=json_mode)
            try:
                args_dict = json.loads(raw_args)
            except Exception as e:
                return McpCliOutput.failure_with_json(EXIT_USAGE, f"invalid JSON in --args: {e}", json_mode=json_mode)
        else:
            args_dict = {}

        call = McpToolCall(name=tool_name, arguments=args_dict, grant_id=grant)
        timeout_val = options.get("timeout") or DEFAULT_EXECUTION_TIMEOUT_SECONDS
        env = service.safe_dispatch_with_timeout(call, timeout_seconds=timeout_val)

        if env.ok:
            msg = json.dumps(env.to_dict()) if json_mode else f"Dispatched tool '{tool_name}': ok"
            return McpCliOutput.success(msg, env.to_dict())
        else:
            code = EXIT_UNAUTHORIZED if env.error_code == ERR_UNAUTHORIZED else EXIT_FAILURE
            return McpCliOutput.failure_with_json(code, env.error_message or "dispatch error", json_mode=json_mode)

    elif subcmd == "sessions":
        prune_val = options.get("prune")
        pruned_count = service.prune_idle_sessions(prune_val) if prune_val is not None else 0
        payload = {"pruned": pruned_count, "status": "ok"}
        if json_mode:
            msg = json.dumps(payload)
        elif prune_val is not None:
            msg = f"Pruned {pruned_count} idle/terminated sessions"
        else:
            msg = "Active sessions enumerated"
        return McpCliOutput.success(msg, payload)

    else:
        return McpCliOutput.failure_with_json(EXIT_USAGE, f"unknown subcommand '{subcmd}'", json_mode=json_mode)
