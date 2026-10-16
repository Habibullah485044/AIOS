"""AI Control Plane MCP Server Core Service (MCPSVC-INV1..MCPSVC-INV5).

Provides execution engine, tool registry, and session lifecycle management for AIOS Phase 3.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
import threading

from .mcp_server_core_data_model import (
    McpToolDefinition,
    McpToolCall,
    McpToolResult,
    McpSessionInfo,
    McpCoreResultEnvelope,
    McpJsonRpcError,
    MAX_TOOLS_COUNT,
    ERR_INTERNAL_ERROR,
    ERR_BOUNDS_EXCEEDED,
)

MAX_ACTIVE_SESSIONS: int = 64
SESSION_IDLE_TIMEOUT_SECONDS: int = 3600
DEFAULT_EXECUTION_TIMEOUT_SECONDS: int = 30
MAX_EXECUTION_TIMEOUT_SECONDS: int = 300

MCPSVC_ERR_SESSION_NOT_FOUND: int = -32004
MCPSVC_ERR_SESSION_CAPACITY_EXCEEDED: int = -32005
MCPSVC_ERR_TOOL_ALREADY_EXISTS: int = -32006
MCPSVC_ERR_TOOL_NOT_FOUND: int = -32601
MCPSVC_ERR_DISPATCH_TIMEOUT: int = -32007


class McpSessionStatus(str, Enum):
    INITIALIZING = "initializing"
    ACTIVE = "active"
    IDLE = "idle"
    TERMINATED = "terminated"


@dataclass
class McpSessionRecord:
    info: McpSessionInfo
    status: McpSessionStatus = McpSessionStatus.ACTIVE
    last_heartbeat: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.info.session_id,
            "client_name": self.info.client_name,
            "client_version": self.info.client_version,
            "status": self.status.value,
            "last_heartbeat": self.last_heartbeat,
        }


class McpServerCoreService:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tools: Dict[str, McpToolDefinition] = {}
        self._sessions: Dict[str, McpSessionRecord] = {}

    def register_tool(self, tool_def: McpToolDefinition) -> None:
        with self._lock:
            if len(self._tools) >= MAX_TOOLS_COUNT:
                raise McpJsonRpcError(ERR_BOUNDS_EXCEEDED, "maximum tool capacity reached")
            if tool_def.name in self._tools:
                raise McpJsonRpcError(MCPSVC_ERR_TOOL_ALREADY_EXISTS, f"tool '{tool_def.name}' already registered")
            self._tools[tool_def.name] = tool_def

    def get_tool(self, name: str) -> Optional[McpToolDefinition]:
        with self._lock:
            return self._tools.get(name)

    def list_tools(self) -> List[McpToolDefinition]:
        with self._lock:
            return list(self._tools.values())

    def create_session(self, session_id: str, client_name: str, client_version: str) -> McpSessionRecord:
        with self._lock:
            if len(self._sessions) >= MAX_ACTIVE_SESSIONS:
                raise McpJsonRpcError(MCPSVC_ERR_SESSION_CAPACITY_EXCEEDED, "maximum active sessions reached")
            info = McpSessionInfo(session_id=session_id, client_name=client_name, client_version=client_version)
            rec = McpSessionRecord(info=info, status=McpSessionStatus.ACTIVE)
            self._sessions[session_id] = rec
            return rec

    def get_session(self, session_id: str) -> Optional[McpSessionRecord]:
        with self._lock:
            return self._sessions.get(session_id)

    def terminate_session(self, session_id: str) -> None:
        with self._lock:
            if session_id not in self._sessions:
                raise McpJsonRpcError(MCPSVC_ERR_SESSION_NOT_FOUND, f"session '{session_id}' not found")
            self._sessions[session_id].status = McpSessionStatus.TERMINATED

    def dispatch_tool_call(self, call: McpToolCall) -> McpToolResult:
        tool = self.get_tool(call.name)
        if not tool:
            raise McpJsonRpcError(MCPSVC_ERR_TOOL_NOT_FOUND, f"tool '{call.name}' not found")
        return McpToolResult.text(f"Executed {tool.name}")

    def safe_dispatch_tool_call(self, call: McpToolCall) -> McpCoreResultEnvelope:
        try:
            res = self.dispatch_tool_call(call)
            return McpCoreResultEnvelope.success(res.to_dict())
        except McpJsonRpcError as e:
            return McpCoreResultEnvelope.error(e.code, e.message)
        except Exception as e:
            return McpCoreResultEnvelope.error(ERR_INTERNAL_ERROR, str(e))
