//! AI Control Plane MCP Server Core MCP/API Surface (T-03095 scaffold / T-03096 impl).
//!
//! Exposes wire protocol routing and JSON-RPC 2.0 adapters for `McpServerCoreService`
//! in compliance with SPEC-MCP-SERVER-CORE-API, ADR-0035 §D-2, and PoR Invariant I-2.

use serde_json::{json, Value};
use crate::mcp_server_core_data_model::*;
use crate::mcp_server_core_service::*;

pub const PROTOCOL_VERSION: &str = "2025-06-18";
pub const SERVER_NAME: &str = "aiosh-mcp";
pub const SERVER_VERSION: &str = "0.1.0";

pub struct McpApiHandler<'a> {
    pub service: &'a McpServerCoreService,
}

impl<'a> McpApiHandler<'a> {
    pub fn new(service: &'a McpServerCoreService) -> Self {
        Self { service }
    }

    pub fn make_error(id: Option<Value>, code: i64, msg: impl Into<String>) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": code,
                "message": msg.into()
            }
        })
    }

    pub fn make_result(id: Option<Value>, res: Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": res
        })
    }

    pub fn handle_ping(&self, id: Option<Value>) -> Value {
        Self::make_result(id, json!({
            "status": "ok",
            "service": "aiosh-mcp",
            "protocolVersion": PROTOCOL_VERSION
        }))
    }

    pub fn handle_initialize(&self, id: Option<Value>, params: Option<&Value>) -> Value {
        let client_info = params.and_then(|p| p.get("clientInfo"));
        let client_name = client_info
            .and_then(|c| c.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown-client");
        let client_ver = client_info
            .and_then(|c| c.get("version"))
            .and_then(|v| v.as_str())
            .unwrap_or("0.0.0");
        let session_id = format!("sess_{}_{}", client_name, id.as_ref().map(|v| v.to_string()).unwrap_or_else(|| "0".to_string()));

        let _ = self.service.create_session(&session_id, client_name, client_ver);

        Self::make_result(id, json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {
                "tools": { "listChanged": false }
            },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION
            },
            "sessionId": session_id
        }))
    }

    pub fn handle_tools_list(&self, id: Option<Value>) -> Value {
        let tools = self.service.list_tools();
        let catalog: Vec<Value> = tools.into_iter().map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema
            })
        }).collect();

        Self::make_result(id, json!({ "tools": catalog }))
    }

    pub fn handle_tools_call(&self, id: Option<Value>, params: Option<&Value>) -> Value {
        let params = match params {
            Some(p) if p.is_object() => p,
            _ => return Self::make_error(id, ERR_INVALID_PARAMS, "missing or invalid params object"),
        };

        let tool_name = match params.get("name").and_then(|v| v.as_str()) {
            Some(n) if !n.is_empty() => n,
            _ => return Self::make_error(id, ERR_INVALID_PARAMS, "missing or invalid tool 'name'"),
        };

        if tool_name.contains('\0') {
            return Self::make_error(id, ERR_INVALID_PARAMS, "prohibited NUL byte in tool name");
        }

        let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
        let args_str = arguments.to_string();
        if args_str.len() > MAX_ARGUMENTS_SIZE {
            return Self::make_error(id, ERR_BOUNDS_EXCEEDED, "arguments payload exceeds 1 MiB limit");
        }

        let grant = params.get("grant").and_then(|v| v.as_str()).map(|s| s.to_string());

        if tool_name.starts_with("aios.admin.") && grant.is_none() {
            return Self::make_error(id, ERR_UNAUTHORIZED, format!("tool '{}' requires capability grant", tool_name));
        }

        let call = match McpToolCall::new(tool_name, arguments, grant) {
            Ok(c) => c,
            Err(e) => return Self::make_error(id, e.code, e.message),
        };

        match self.service.dispatch_tool_call(call) {
            Ok(tool_res) => {
                Self::make_result(id, json!({
                    "content": tool_res.content,
                    "isError": tool_res.is_error
                }))
            }
            Err(err) => {
                Self::make_error(id, err.code, err.message)
            }
        }
    }

    pub fn handle_raw_message(&self, raw: &str) -> Value {
        let val: Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(e) => return Self::make_error(None, -32700, format!("Parse error: {}", e)),
        };

        let obj = match val.as_object() {
            Some(o) => o,
            None => return Self::make_error(None, ERR_INVALID_REQUEST, "JSON-RPC request must be an object"),
        };

        let req_id = obj.get("id").cloned();

        let jsonrpc = obj.get("jsonrpc").and_then(|v| v.as_str());
        if jsonrpc != Some("2.0") {
            return Self::make_error(req_id, ERR_INVALID_REQUEST, "jsonrpc version must be '2.0'");
        }

        let method = match obj.get("method").and_then(|v| v.as_str()) {
            Some(m) => m,
            None => return Self::make_error(req_id, ERR_INVALID_REQUEST, "missing or invalid method"),
        };

        let params = obj.get("params");

        match method {
            "ping" => self.handle_ping(req_id),
            "initialize" => self.handle_initialize(req_id, params),
            "tools/list" => self.handle_tools_list(req_id),
            "tools/call" => self.handle_tools_call(req_id, params),
            _ => Self::make_error(req_id, ERR_METHOD_NOT_FOUND, format!("Method '{}' not found", method)),
        }
    }
}
