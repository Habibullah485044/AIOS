//! MCP Server Core Data Model (MCPDM-INV1..MCPDM-INV5).
//!
//! Provides the canonical domain primitives, JSON-RPC 2.0 framing, capability negotiation,
//! tool call structures, content block types, and ADR-0035 envelopes for AIOS Phase 3 MCP Server Core.

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpJsonRpcRequest {
    pub jsonrpc: String,
    pub id: McpRequestId,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpJsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpToolCall {
    pub name: String,
    pub arguments: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,
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

impl McpJsonRpcRequest {
    pub fn validate_scaffold(&self) -> Result<(), &'static str> {
        if self.jsonrpc != "2.0" {
            return Err("jsonrpc must be 2.0");
        }
        if self.method.is_empty() || self.method.len() > MAX_METHOD_NAME_LEN {
            return Err("invalid method name length");
        }
        Ok(())
    }
}
