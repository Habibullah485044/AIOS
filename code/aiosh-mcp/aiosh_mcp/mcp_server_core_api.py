"""AI Control Plane MCP Server Core MCP/API Surface (T-03095 scaffold / T-03096 impl).

Wire protocol handler and JSON-RPC 2.0 adapter for McpServerCoreService.
Conforms to SPEC-MCP-SERVER-CORE-API, ADR-0035 §D-2, ADR-0035 §AF-2, and PoR Invariant I-2.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Union

from .mcp_server_core_data_model import (
    McpToolDefinition,
    McpToolCall,
    McpToolResult,
    MAX_ARGUMENTS_SIZE,
    ERR_INVALID_REQUEST,
    ERR_METHOD_NOT_FOUND,
    ERR_INVALID_PARAMS,
    ERR_INTERNAL_ERROR,
    ERR_BOUNDS_EXCEEDED,
    ERR_UNAUTHORIZED,
)
from .mcp_server_core_service import (
    McpServerCoreService,
    MCPSVC_ERR_TOOL_NOT_FOUND,
)

PROTOCOL_VERSION: str = "2025-06-18"
SERVER_NAME: str = "aiosh-mcp"
SERVER_VERSION: str = "0.1.0"


def make_jsonrpc_error(req_id: Optional[Union[str, int]], code: int, message: str, data: Any = None) -> Dict[str, Any]:
    err: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": err,
    }


def make_jsonrpc_result(req_id: Optional[Union[str, int]], result: Any) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": result,
    }


class McpApiHandler:
    def __init__(self, service: Optional[McpServerCoreService] = None) -> None:
        self.service: McpServerCoreService = service or McpServerCoreService()

    def handle_ping(self, req_id: Optional[Union[str, int]]) -> Dict[str, Any]:
        """Handle ping method (liveness check)."""
        return make_jsonrpc_result(req_id, {"status": "ok", "service": "aiosh-mcp"})

    def handle_initialize(
        self, req_id: Optional[Union[str, int]], params: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Handle initialize method per MCP specification."""
        if params is None:
            params = {}
        client_info = params.get("clientInfo", {})
        client_name = client_info.get("name", "unknown-client")
        client_ver = client_info.get("version", "0.0.0")
        session_id = f"sess_{client_name}_{req_id or 0}"

        # Register session in service
        self.service.create_session(session_id, client_name, client_ver)

        return make_jsonrpc_result(
            req_id,
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": False},
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION,
                },
                "sessionId": session_id,
            },
        )

    def handle_tools_list(
        self, req_id: Optional[Union[str, int]], params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Handle tools/list method."""
        tools = self.service.list_tools()
        catalog = [t.to_dict() for t in tools]
        return make_jsonrpc_result(req_id, {"tools": catalog})

    def handle_tools_call(
        self, req_id: Optional[Union[str, int]], params: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Handle tools/call method with gating and bounds enforcement."""
        if not params or not isinstance(params, dict):
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, "missing params object")

        tool_name = params.get("name")
        if not tool_name or not isinstance(tool_name, str):
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, "missing or invalid tool 'name'")

        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, "arguments must be a JSON object")

        grant = params.get("grant")

        # Security Check: validate payload size
        args_str = json.dumps(arguments)
        if len(args_str.encode("utf-8")) > MAX_ARGUMENTS_SIZE:
            return make_jsonrpc_error(req_id, ERR_BOUNDS_EXCEEDED, "arguments payload exceeds 1 MiB limit")

        # Security Check: NUL byte injection
        def _has_nul(v: Any) -> bool:
            if isinstance(v, str):
                return "\0" in v
            if isinstance(v, dict):
                return any(_has_nul(k) or _has_nul(val) for k, val in v.items())
            if isinstance(v, list):
                return any(_has_nul(item) for item in v)
            return False

        if "\0" in tool_name or _has_nul(arguments) or "\\u0000" in args_str:
            return make_jsonrpc_error(req_id, ERR_INVALID_PARAMS, "prohibited NUL byte detected")

        # Capability Gating: aios.admin.* tools require grant
        if tool_name.startswith("aios.admin.") and not grant:
            return make_jsonrpc_error(req_id, ERR_UNAUTHORIZED, f"tool '{tool_name}' requires capability grant")

        # Dispatch via core service
        try:
            tool_call = McpToolCall(name=tool_name, arguments=arguments, grant_id=grant)
            tool_res = self.service.dispatch_tool_call(tool_call)
        except Exception as e:
            return make_jsonrpc_error(req_id, MCPSVC_ERR_TOOL_NOT_FOUND, str(e))

        return make_jsonrpc_result(
            req_id,
            {
                "content": [b.to_dict() for b in tool_res.content],
                "isError": tool_res.is_error,
            },
        )

    def handle_raw_message(self, message: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Parse raw incoming JSON or dict and dispatch to JSON-RPC handler."""
        if isinstance(message, str):
            try:
                data = json.loads(message)
            except Exception as e:
                return make_jsonrpc_error(None, -32700, f"Parse error: {e}")
        elif isinstance(message, dict):
            data = message
        else:
            return make_jsonrpc_error(None, ERR_INVALID_REQUEST, "invalid request type")

        if not isinstance(data, dict):
            return make_jsonrpc_error(None, ERR_INVALID_REQUEST, "JSON-RPC request must be an object")

        if data.get("jsonrpc") != "2.0":
            return make_jsonrpc_error(data.get("id"), ERR_INVALID_REQUEST, "jsonrpc version must be '2.0'")

        method = data.get("method")
        req_id = data.get("id")
        params = data.get("params")

        if not method or not isinstance(method, str):
            return make_jsonrpc_error(req_id, ERR_INVALID_REQUEST, "missing or invalid 'method'")

        if method == "ping":
            return self.handle_ping(req_id)
        elif method == "initialize":
            return self.handle_initialize(req_id, params)
        elif method == "tools/list":
            return self.handle_tools_list(req_id, params)
        elif method == "tools/call":
            return self.handle_tools_call(req_id, params)
        else:
            return make_jsonrpc_error(req_id, ERR_METHOD_NOT_FOUND, f"Method '{method}' not found")


_GLOBAL_API_HANDLER: McpApiHandler = McpApiHandler()


def get_api_handler() -> McpApiHandler:
    return _GLOBAL_API_HANDLER


def register_mcp_api_tools(mcp_app: Any, handler: Optional[McpApiHandler] = None) -> None:
    """Register MCP Server Core API tools with FastMCP (T-03098)."""
    api = handler or _GLOBAL_API_HANDLER

    @mcp_app.tool()
    def aios_mcp_api_ping() -> dict:
        """Ping the MCP Server Core wire API endpoint."""
        return api.handle_ping(1)

    @mcp_app.tool()
    def aios_mcp_api_jsonrpc(request: str) -> dict:
        """Route a raw JSON-RPC 2.0 request through MCP Server Core API handler."""
        return api.handle_raw_message(request)

