"""AI Control Plane MCP Server Core Data Model (MCPDM-INV1..MCPDM-INV5).

Defines canonical domain primitives, JSON-RPC 2.0 wire framing, session models,
tool calls, content blocks, and ADR-0035 result envelopes for AIOS Phase 3.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Union
import json
import re

PROTOCOL_VERSION: str = "2025-06-18"
MAX_TOOL_NAME_LEN: int = 64
MAX_METHOD_NAME_LEN: int = 64
MAX_SESSION_ID_LEN: int = 64
MAX_TOOL_DESC_LEN: int = 1024
MAX_SCHEMA_SIZE: int = 64 * 1024        # 64 KiB
MAX_ARGUMENTS_SIZE: int = 1024 * 1024   # 1 MiB
MAX_PAYLOAD_SIZE: int = 10 * 1024 * 1024 # 10 MiB
MAX_TOOLS_COUNT: int = 256
MAX_CONTENT_BLOCKS: int = 32

# Standard JSON-RPC Error Codes
ERR_PARSE_ERROR: int = -32700
ERR_INVALID_REQUEST: int = -32600
ERR_METHOD_NOT_FOUND: int = -32601
ERR_INVALID_PARAMS: int = -32602
ERR_INTERNAL_ERROR: int = -32603

# Application / AIOS Specific Codes
ERR_UNAUTHORIZED: int = -32001
ERR_BOUNDS_EXCEEDED: int = -32002
ERR_SANITIZATION_FAILED: int = -32003
ERR_SESSION_EXPIRED: int = -32004


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class McpJsonRpcError:
    code: int
    message: str
    data: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            d["data"] = self.data
        return d


@dataclass
class McpJsonRpcRequest:
    jsonrpc: str
    id: Union[str, int]
    method: str
    params: Optional[Dict[str, Any]] = None

    def validate_scaffold(self) -> None:
        if self.jsonrpc != "2.0":
            raise ValueError("jsonrpc must be '2.0'")
        if not self.method or len(self.method) > MAX_METHOD_NAME_LEN:
            raise ValueError("invalid method name length")

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"jsonrpc": self.jsonrpc, "id": self.id, "method": self.method}
        if self.params is not None:
            d["params"] = self.params
        return d


@dataclass
class McpJsonRpcResponse:
    jsonrpc: str
    id: Union[str, int]
    result: Optional[Any] = None
    error: Optional[McpJsonRpcError] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"jsonrpc": self.jsonrpc, "id": self.id}
        if self.error is not None:
            d["error"] = self.error.to_dict()
        else:
            d["result"] = self.result
        return d


@dataclass
class McpToolDefinition:
    name: str
    description: str
    input_schema: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


@dataclass
class McpToolCall:
    name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    grant_id: Optional[str] = None


@dataclass
class McpContentBlock:
    type: Literal["text", "image", "resource"]
    text: Optional[str] = None
    data: Optional[str] = None
    mime_type: Optional[str] = None
    uri: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"type": self.type}
        if self.text is not None:
            d["text"] = self.text
        if self.data is not None:
            d["data"] = self.data
        if self.mime_type is not None:
            d["mimeType"] = self.mime_type
        if self.uri is not None:
            d["uri"] = self.uri
        return d


@dataclass
class McpToolResult:
    content: List[McpContentBlock] = field(default_factory=list)
    is_error: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": [b.to_dict() for b in self.content],
            "isError": self.is_error,
        }


@dataclass
class McpServerCapabilities:
    tools: bool = True
    resources: bool = False
    prompts: bool = False
    logging: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tools": {"listChanged": True} if self.tools else None,
            "logging": {} if self.logging else None,
        }


@dataclass
class McpSessionInfo:
    session_id: str
    client_name: str
    client_version: str
    protocol_version: str = PROTOCOL_VERSION
    capabilities: McpServerCapabilities = field(default_factory=McpServerCapabilities)
    created_at: str = field(default_factory=_utcnow_iso)


@dataclass
class McpCoreResultEnvelope:
    status: str
    ok: bool
    data: Optional[Any] = None
    error_code: Optional[int] = None
    error_message: Optional[str] = None
    timestamp: str = field(default_factory=_utcnow_iso)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "status": self.status,
            "ok": self.ok,
            "timestamp": self.timestamp,
        }
        if self.data is not None:
            d["data"] = self.data
        if self.error_code is not None:
            d["error_code"] = self.error_code
        if self.error_message is not None:
            d["error_message"] = self.error_message
        return d
