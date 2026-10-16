//! MCP Server Core Data Model (MCPDM-INV1..MCPDM-INV5).
//!
//! Canonical domain primitives, JSON-RPC 2.0 framing, capability negotiation,
//! tool call structures, content block types, and ADR-0035 envelopes for AIOS Phase 3.

use std::fmt;
use serde::{Deserialize, Serialize};
use crate::canonical::utcnow_iso;

pub const PROTOCOL_VERSION: &str = "2025-06-18";
pub const MAX_TOOL_NAME_LEN: usize = 64;
pub const MAX_METHOD_NAME_LEN: usize = 64;
pub const MAX_SESSION_ID_LEN: usize = 64;
pub const MAX_TOOL_DESC_LEN: usize = 1024;
pub const MAX_SCHEMA_SIZE: usize = 64 * 1024;        // 64 KiB
pub const MAX_ARGUMENTS_SIZE: usize = 1024 * 1024;   // 1 MiB
pub const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024; // 10 MiB
pub const MAX_TOOLS_COUNT: usize = 256;
pub const MAX_CONTENT_BLOCKS: usize = 32;

// Standard JSON-RPC Error Codes
pub const ERR_PARSE_ERROR: i64 = -32700;
pub const ERR_INVALID_REQUEST: i64 = -32600;
pub const ERR_METHOD_NOT_FOUND: i64 = -32601;
pub const ERR_INVALID_PARAMS: i64 = -32602;
pub const ERR_INTERNAL_ERROR: i64 = -32603;

// Application / AIOS Specific Codes
pub const ERR_UNAUTHORIZED: i64 = -32001;
pub const ERR_BOUNDS_EXCEEDED: i64 = -32002;
pub const ERR_SANITIZATION_FAILED: i64 = -32003;
pub const ERR_SESSION_EXPIRED: i64 = -32004;

/// Checks for Trojan Source and control character injection (MCPDM-INV3).
pub fn contains_bidi_or_control(s: &str) -> bool {
    s.chars().any(|c| {
        let u = c as u32;
        // ASCII control chars
        (u <= 0x1F || u == 0x7F)
        // Unicode Bidirectional overrides (Trojan Source: U+202A..U+202E, U+2066..U+2069)
        || (0x202A..=0x202E).contains(&u)
        || (0x2066..=0x2069).contains(&u)
    })
}

/// Validates identifiers: alphanumeric, hyphen, underscore, dot (MCPDM-INV3).
pub fn validate_identifier(id: &str, max_len: usize) -> Result<(), McpJsonRpcError> {
    if id.is_empty() {
        return Err(McpJsonRpcError::new(ERR_INVALID_PARAMS, "identifier cannot be empty"));
    }
    if id.len() > max_len {
        return Err(McpJsonRpcError::new(
            ERR_BOUNDS_EXCEEDED,
            format!("identifier length {} exceeds limit {}", id.len(), max_len),
        ));
    }
    if contains_bidi_or_control(id) {
        return Err(McpJsonRpcError::new(
            ERR_SANITIZATION_FAILED,
            "identifier contains disallowed control characters or bidi overrides",
        ));
    }
    for c in id.chars() {
        if !c.is_ascii_alphanumeric() && c != '_' && c != '-' && c != '.' {
            return Err(McpJsonRpcError::new(
                ERR_INVALID_PARAMS,
                format!("identifier contains invalid character '{}'", c),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum McpRequestId {
    Number(i64),
    String(String),
}

impl Default for McpRequestId {
    fn default() -> Self {
        McpRequestId::Number(1)
    }
}

impl fmt::Display for McpRequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            McpRequestId::Number(n) => write!(f, "{}", n),
            McpRequestId::String(s) => write!(f, "\"{}\"", s),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpJsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl McpJsonRpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(code: i64, message: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpJsonRpcRequest {
    pub jsonrpc: String,
    pub id: McpRequestId,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

impl McpJsonRpcRequest {
    pub fn new(id: McpRequestId, method: impl Into<String>, params: Option<serde_json::Value>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.into(),
            params,
        }
    }

    pub fn validate(&self) -> Result<(), McpJsonRpcError> {
        if self.jsonrpc != "2.0" {
            return Err(McpJsonRpcError::new(
                ERR_INVALID_REQUEST,
                "jsonrpc version must be exactly '2.0'",
            ));
        }
        if self.method.is_empty() {
            return Err(McpJsonRpcError::new(
                ERR_INVALID_REQUEST,
                "method name cannot be empty",
            ));
        }
        if self.method.len() > MAX_METHOD_NAME_LEN {
            return Err(McpJsonRpcError::new(
                ERR_BOUNDS_EXCEEDED,
                format!("method length {} exceeds max {}", self.method.len(), MAX_METHOD_NAME_LEN),
            ));
        }
        if contains_bidi_or_control(&self.method) {
            return Err(McpJsonRpcError::new(
                ERR_SANITIZATION_FAILED,
                "method name contains control characters or bidirectional overrides",
            ));
        }
        Ok(())
    }

    pub fn validate_scaffold(&self) -> Result<(), &'static str> {
        self.validate().map(|_| ()).map_err(|_| "validation failed")
    }

    pub fn from_json_str(s: &str) -> Result<Self, McpJsonRpcError> {
        if s.len() > MAX_PAYLOAD_SIZE {
            return Err(McpJsonRpcError::new(
                ERR_BOUNDS_EXCEEDED,
                format!("payload size {} exceeds limit {}", s.len(), MAX_PAYLOAD_SIZE),
            ));
        }
        let req: McpJsonRpcRequest = serde_json::from_str(s)
            .map_err(|e| McpJsonRpcError::new(ERR_PARSE_ERROR, format!("parse error: {}", e)))?;
        req.validate()?;
        Ok(req)
    }

    pub fn to_json_str(&self) -> Result<String, McpJsonRpcError> {
        serde_json::to_string(self)
            .map_err(|e| McpJsonRpcError::new(ERR_INTERNAL_ERROR, format!("serialization error: {}", e)))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpJsonRpcResponse {
    pub jsonrpc: String,
    pub id: McpRequestId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpJsonRpcError>,
}

impl McpJsonRpcResponse {
    pub fn success(id: McpRequestId, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: McpRequestId, error: McpJsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }

    pub fn from_json_str(s: &str) -> Result<Self, McpJsonRpcError> {
        if s.len() > MAX_PAYLOAD_SIZE {
            return Err(McpJsonRpcError::new(
                ERR_BOUNDS_EXCEEDED,
                format!("payload size {} exceeds limit {}", s.len(), MAX_PAYLOAD_SIZE),
            ));
        }
        serde_json::from_str(s)
            .map_err(|e| McpJsonRpcError::new(ERR_PARSE_ERROR, format!("parse error: {}", e)))
    }

    pub fn to_json_str(&self) -> Result<String, McpJsonRpcError> {
        serde_json::to_string(self)
            .map_err(|e| McpJsonRpcError::new(ERR_INTERNAL_ERROR, format!("serialization error: {}", e)))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

impl McpToolDefinition {
    pub fn new(name: impl Into<String>, description: impl Into<String>, input_schema: serde_json::Value) -> Result<Self, McpJsonRpcError> {
        let name_str = name.into();
        let desc_str = description.into();
        validate_identifier(&name_str, MAX_TOOL_NAME_LEN)?;
        if desc_str.len() > MAX_TOOL_DESC_LEN {
            return Err(McpJsonRpcError::new(
                ERR_BOUNDS_EXCEEDED,
                format!("description length {} exceeds max {}", desc_str.len(), MAX_TOOL_DESC_LEN),
            ));
        }
        let schema_len = serde_json::to_string(&input_schema).unwrap_or_default().len();
        if schema_len > MAX_SCHEMA_SIZE {
            return Err(McpJsonRpcError::new(
                ERR_BOUNDS_EXCEEDED,
                format!("input schema size {} exceeds max {}", schema_len, MAX_SCHEMA_SIZE),
            ));
        }
        Ok(Self {
            name: name_str,
            description: desc_str,
            input_schema,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpToolCall {
    pub name: String,
    pub arguments: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
}

impl McpToolCall {
    pub fn new(name: impl Into<String>, arguments: serde_json::Value, grant_id: Option<String>) -> Result<Self, McpJsonRpcError> {
        let name_str = name.into();
        validate_identifier(&name_str, MAX_TOOL_NAME_LEN)?;
        let args_len = serde_json::to_string(&arguments).unwrap_or_default().len();
        if args_len > MAX_ARGUMENTS_SIZE {
            return Err(McpJsonRpcError::new(
                ERR_BOUNDS_EXCEEDED,
                format!("arguments size {} exceeds limit {}", args_len, MAX_ARGUMENTS_SIZE),
            ));
        }
        if let Some(ref gid) = grant_id {
            validate_identifier(gid, 64)?;
        }
        Ok(Self {
            name: name_str,
            arguments,
            grant_id,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpContentBlock {
    Text {
        text: String,
    },
    Image {
        data: String,
        mime_type: String,
    },
    Resource {
        uri: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        mime_type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        text: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpToolResult {
    pub content: Vec<McpContentBlock>,
    pub is_error: bool,
}

impl McpToolResult {
    pub fn text(t: impl Into<String>) -> Self {
        Self {
            content: vec![McpContentBlock::Text { text: t.into() }],
            is_error: false,
        }
    }

    pub fn error(t: impl Into<String>) -> Self {
        Self {
            content: vec![McpContentBlock::Text { text: t.into() }],
            is_error: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerCapabilities {
    pub tools: bool,
    pub resources: bool,
    pub prompts: bool,
    pub logging: bool,
}

impl Default for McpServerCapabilities {
    fn default() -> Self {
        Self {
            tools: true,
            resources: false,
            prompts: false,
            logging: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpSessionInfo {
    pub session_id: String,
    pub client_name: String,
    pub client_version: String,
    pub protocol_version: String,
    pub capabilities: McpServerCapabilities,
    pub created_at: String,
}

impl McpSessionInfo {
    pub fn new(session_id: impl Into<String>, client_name: impl Into<String>, client_version: impl Into<String>) -> Result<Self, McpJsonRpcError> {
        let sid = session_id.into();
        let cname = client_name.into();
        let cver = client_version.into();
        validate_identifier(&sid, MAX_SESSION_ID_LEN)?;
        if cname.len() > 64 || cver.len() > 64 {
            return Err(McpJsonRpcError::new(ERR_BOUNDS_EXCEEDED, "client info length exceeds limit"));
        }
        Ok(Self {
            session_id: sid,
            client_name: cname,
            client_version: cver,
            protocol_version: PROTOCOL_VERSION.to_string(),
            capabilities: McpServerCapabilities::default(),
            created_at: utcnow_iso(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpCoreResultEnvelope<T> {
    pub status: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub timestamp: String,
}

impl<T> McpCoreResultEnvelope<T> {
    pub fn success(data: T) -> Self {
        Self {
            status: "success".to_string(),
            ok: true,
            data: Some(data),
            error_code: None,
            error_message: None,
            timestamp: utcnow_iso(),
        }
    }

    pub fn error(code: i64, message: impl Into<String>) -> Self {
        Self {
            status: "error".to_string(),
            ok: false,
            data: None,
            error_code: Some(code),
            error_message: Some(message.into()),
            timestamp: utcnow_iso(),
        }
    }
}
