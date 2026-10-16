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

IDENTIFIER_RE = re.compile(r"^[a-zA-Z0-9_\.\-]+$")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def contains_bidi_or_control(s: str) -> bool:
    for c in s:
        u = ord(c)
        if (u <= 0x1F or u == 0x7F) or (0x202A <= u <= 0x202E) or (0x2066 <= u <= 0x2069):
            return True
    return False


def validate_identifier(ident: str, max_len: int) -> None:
    if not ident:
        raise ValueError("identifier cannot be empty")
    if len(ident) > max_len:
        raise ValueError(f"identifier length {len(ident)} exceeds limit {max_len}")
    if contains_bidi_or_control(ident):
        raise ValueError("identifier contains disallowed control characters or bidi overrides")
    if not IDENTIFIER_RE.match(ident):
        raise ValueError(f"identifier contains invalid characters: '{ident}'")


@dataclass
class McpJsonRpcError(Exception):
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

    def validate(self) -> None:
        if self.jsonrpc != "2.0":
            raise McpJsonRpcError(ERR_INVALID_REQUEST, "jsonrpc version must be exactly '2.0'")
        if not self.method:
            raise McpJsonRpcError(ERR_INVALID_REQUEST, "method name cannot be empty")
        if len(self.method) > MAX_METHOD_NAME_LEN:
            raise McpJsonRpcError(
                ERR_BOUNDS_EXCEEDED,
                f"method length {len(self.method)} exceeds max {MAX_METHOD_NAME_LEN}",
            )
        if contains_bidi_or_control(self.method):
            raise McpJsonRpcError(
                ERR_SANITIZATION_FAILED,
                "method contains control characters or bidi overrides",
            )

    def validate_scaffold(self) -> None:
        self.validate()

    @classmethod
    def from_json_str(cls, s: str) -> McpJsonRpcRequest:
        if len(s.encode("utf-8")) > MAX_PAYLOAD_SIZE:
            raise McpJsonRpcError(ERR_BOUNDS_EXCEEDED, "payload exceeds size limit")
        try:
            d = json.loads(s)
        except Exception as e:
            raise McpJsonRpcError(ERR_PARSE_ERROR, f"parse error: {e}")
        if not isinstance(d, dict):
            raise McpJsonRpcError(ERR_INVALID_REQUEST, "request must be an object")
        req = cls(
            jsonrpc=d.get("jsonrpc", ""),
            id=d.get("id", 1),
            method=d.get("method", ""),
            params=d.get("params"),
        )
        req.validate()
        return req

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"jsonrpc": self.jsonrpc, "id": self.id, "method": self.method}
        if self.params is not None:
            d["params"] = self.params
        return d

    def to_json_str(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class McpJsonRpcResponse:
    jsonrpc: str
    id: Union[str, int]
    result: Optional[Any] = None
    error: Optional[McpJsonRpcError] = None

    @classmethod
    def success(cls, req_id: Union[str, int], result: Any) -> McpJsonRpcResponse:
        return cls(jsonrpc="2.0", id=req_id, result=result, error=None)

    @classmethod
    def error_resp(cls, req_id: Union[str, int], err: McpJsonRpcError) -> McpJsonRpcResponse:
        return cls(jsonrpc="2.0", id=req_id, result=None, error=err)

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"jsonrpc": self.jsonrpc, "id": self.id}
        if self.error is not None:
            d["error"] = self.error.to_dict()
        else:
            d["result"] = self.result
        return d

    def to_json_str(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class McpToolDefinition:
    name: str
    description: str
    input_schema: Dict[str, Any]

    def __post_init__(self) -> None:
        try:
            validate_identifier(self.name, MAX_TOOL_NAME_LEN)
        except ValueError as e:
            raise McpJsonRpcError(ERR_INVALID_PARAMS, str(e))
        if len(self.description) > MAX_TOOL_DESC_LEN:
            raise McpJsonRpcError(ERR_BOUNDS_EXCEEDED, "description exceeds max length")
        raw_schema = json.dumps(self.input_schema)
        if len(raw_schema.encode("utf-8")) > MAX_SCHEMA_SIZE:
            raise McpJsonRpcError(ERR_BOUNDS_EXCEEDED, "input schema exceeds max size")

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

    def __post_init__(self) -> None:
        try:
            validate_identifier(self.name, MAX_TOOL_NAME_LEN)
            if self.grant_id:
                validate_identifier(self.grant_id, 64)
        except ValueError as e:
            raise McpJsonRpcError(ERR_INVALID_PARAMS, str(e))
        raw_args = json.dumps(self.arguments)
        if len(raw_args.encode("utf-8")) > MAX_ARGUMENTS_SIZE:
            raise McpJsonRpcError(ERR_BOUNDS_EXCEEDED, "arguments exceed max size limit")


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

    @classmethod
    def text(cls, t: str) -> McpToolResult:
        return cls(content=[McpContentBlock(type="text", text=t)], is_error=False)

    @classmethod
    def error(cls, t: str) -> McpToolResult:
        return cls(content=[McpContentBlock(type="text", text=t)], is_error=True)

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

    def __post_init__(self) -> None:
        try:
            validate_identifier(self.session_id, MAX_SESSION_ID_LEN)
        except ValueError as e:
            raise McpJsonRpcError(ERR_INVALID_PARAMS, str(e))
        if len(self.client_name) > 64 or len(self.client_version) > 64:
            raise McpJsonRpcError(ERR_BOUNDS_EXCEEDED, "client info length exceeds limit")


@dataclass
class McpCoreResultEnvelope:
    status: str
    ok: bool
    data: Optional[Any] = None
    error_code: Optional[int] = None
    error_message: Optional[str] = None
    timestamp: str = field(default_factory=_utcnow_iso)

    @classmethod
    def success(cls, data: Any) -> McpCoreResultEnvelope:
        return cls(status="success", ok=True, data=data)

    @classmethod
    def error(cls, code: int, message: str) -> McpCoreResultEnvelope:
        return cls(status="error", ok=False, error_code=code, error_message=message)

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


def register_mcp_core_tools(mcp_app: Any) -> None:
    """Register MCP Server Core diagnostic and inspection tools with FastMCP."""
    @mcp_app.tool()
    def aios_mcp_core_status(session_id: str = "default_session") -> dict:
        """Inspect the AI Control Plane MCP Server Core data model and capabilities."""
        try:
            session = McpSessionInfo(
                session_id=session_id,
                client_name="aios-control-plane",
                client_version="0.1.0",
            )
            data = {
                "session_id": session.session_id,
                "protocol_version": session.protocol_version,
                "capabilities": session.capabilities.to_dict(),
                "created_at": session.created_at,
            }
            env = McpCoreResultEnvelope.success(data)
            return env.to_dict()
        except McpJsonRpcError as e:
            return McpCoreResultEnvelope.error(e.code, e.message).to_dict()
        except Exception as e:
            return McpCoreResultEnvelope.error(ERR_INTERNAL_ERROR, str(e)).to_dict()

