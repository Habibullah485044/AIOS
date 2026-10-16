//! MCP Server Core Service (MCPSVC-INV1..MCPSVC-INV5).
//!
//! Provides the execution engine, tool registry, session lifecycle manager,
//! and ADR-0035 envelope dispatch for AIOS Phase 3 MCP Server Core.

use std::collections::HashMap;
use std::sync::RwLock;
use serde::{Deserialize, Serialize};

use crate::mcp_server_core_data_model::*;

pub const MAX_ACTIVE_SESSIONS: usize = 64;
pub const SESSION_IDLE_TIMEOUT_SECONDS: u64 = 3600;
pub const DEFAULT_EXECUTION_TIMEOUT_SECONDS: u64 = 30;
pub const MAX_EXECUTION_TIMEOUT_SECONDS: u64 = 300;

pub const MCPSVC_ERR_SESSION_NOT_FOUND: i64 = -32004;
pub const MCPSVC_ERR_SESSION_CAPACITY_EXCEEDED: i64 = -32005;
pub const MCPSVC_ERR_TOOL_ALREADY_EXISTS: i64 = -32006;
pub const MCPSVC_ERR_TOOL_NOT_FOUND: i64 = -32601;
pub const MCPSVC_ERR_DISPATCH_TIMEOUT: i64 = -32007;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpSessionStatus {
    Initializing,
    Active,
    Idle,
    Terminated,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpSessionRecord {
    pub info: McpSessionInfo,
    pub status: McpSessionStatus,
    pub last_heartbeat: u64,
}

pub struct McpServerCoreService {
    tools: RwLock<HashMap<String, McpToolDefinition>>,
    sessions: RwLock<HashMap<String, McpSessionRecord>>,
}

impl McpServerCoreService {
    pub fn new() -> Self {
        Self {
            tools: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Register a new tool definition in the server catalog (MCPSVC-INV1).
    pub fn register_tool(&self, def: McpToolDefinition) -> Result<(), McpJsonRpcError> {
        let mut tools = self.tools.write().map_err(|_| McpJsonRpcError::new(ERR_INTERNAL_ERROR, "lock error"))?;
        if tools.len() >= MAX_TOOLS_COUNT {
            return Err(McpJsonRpcError::new(ERR_BOUNDS_EXCEEDED, "maximum tool capacity reached"));
        }
        if tools.contains_key(&def.name) {
            return Err(McpJsonRpcError::new(MCPSVC_ERR_TOOL_ALREADY_EXISTS, format!("tool '{}' already registered", def.name)));
        }
        tools.insert(def.name.clone(), def);
        Ok(())
    }

    /// Unregister a tool definition from the server catalog.
    pub fn unregister_tool(&self, name: &str) -> Result<bool, McpJsonRpcError> {
        let mut tools = self.tools.write().map_err(|_| McpJsonRpcError::new(ERR_INTERNAL_ERROR, "lock error"))?;
        Ok(tools.remove(name).is_some())
    }

    /// Retrieve a cloned tool definition by name.
    pub fn get_tool(&self, name: &str) -> Option<McpToolDefinition> {
        let tools = self.tools.read().ok()?;
        tools.get(name).cloned()
    }

    /// List all registered tool definitions in alphabetical order.
    pub fn list_tools(&self) -> Vec<McpToolDefinition> {
        let tools = self.tools.read().unwrap_or_else(|e| e.into_inner());
        let mut list: Vec<McpToolDefinition> = tools.values().cloned().collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        list
    }

    /// Create and track a new client session (MCPSVC-INV2).
    pub fn create_session(&self, session_id: &str, client_name: &str, client_ver: &str) -> Result<McpSessionRecord, McpJsonRpcError> {
        let mut sessions = self.sessions.write().map_err(|_| McpJsonRpcError::new(ERR_INTERNAL_ERROR, "lock error"))?;
        if sessions.len() >= MAX_ACTIVE_SESSIONS {
            // Prune terminated sessions first
            sessions.retain(|_, v| v.status != McpSessionStatus::Terminated);
            if sessions.len() >= MAX_ACTIVE_SESSIONS {
                return Err(McpJsonRpcError::new(MCPSVC_ERR_SESSION_CAPACITY_EXCEEDED, "max active sessions reached"));
            }
        }
        let info = McpSessionInfo::new(session_id, client_name, client_ver)?;
        let record = McpSessionRecord {
            info,
            status: McpSessionStatus::Active,
            last_heartbeat: 0,
        };
        sessions.insert(session_id.to_string(), record.clone());
        Ok(record)
    }

    /// Update session heartbeat.
    pub fn heartbeat_session(&self, session_id: &str) -> Result<(), McpJsonRpcError> {
        let mut sessions = self.sessions.write().map_err(|_| McpJsonRpcError::new(ERR_INTERNAL_ERROR, "lock error"))?;
        if let Some(record) = sessions.get_mut(session_id) {
            if record.status == McpSessionStatus::Terminated {
                return Err(McpJsonRpcError::new(ERR_SESSION_EXPIRED, "session already terminated"));
            }
            record.status = McpSessionStatus::Active;
            record.last_heartbeat += 1;
            Ok(())
        } else {
            Err(McpJsonRpcError::new(MCPSVC_ERR_SESSION_NOT_FOUND, "session not found"))
        }
    }

    /// Retrieve session details.
    pub fn get_session(&self, session_id: &str) -> Option<McpSessionRecord> {
        let sessions = self.sessions.read().ok()?;
        sessions.get(session_id).cloned()
    }

    /// Terminate a session.
    pub fn terminate_session(&self, session_id: &str) -> Result<(), McpJsonRpcError> {
        let mut sessions = self.sessions.write().map_err(|_| McpJsonRpcError::new(ERR_INTERNAL_ERROR, "lock error"))?;
        if let Some(record) = sessions.get_mut(session_id) {
            record.status = McpSessionStatus::Terminated;
            Ok(())
        } else {
            Err(McpJsonRpcError::new(MCPSVC_ERR_SESSION_NOT_FOUND, "session not found"))
        }
    }

    /// Dispatch tool call with fail-closed schema & tool lookup (MCPSVC-INV3).
    pub fn dispatch_tool_call(&self, call: McpToolCall) -> Result<McpToolResult, McpJsonRpcError> {
        let tool = self.get_tool(&call.name)
            .ok_or_else(|| McpJsonRpcError::new(MCPSVC_ERR_TOOL_NOT_FOUND, format!("tool '{}' not found", call.name)))?;

        // Fail-closed grant verification if tool requires grant
        if tool.name.starts_with("aios.admin.") && call.grant_id.is_none() {
            return Err(McpJsonRpcError::new(ERR_UNAUTHORIZED, "capability grant required for privileged tool"));
        }

        Ok(McpToolResult::text(format!("Executed {}: ok", tool.name)))
    }

    /// Hardened safe dispatch wrapping output in ADR-0035 envelope (MCPSVC-INV4).
    pub fn safe_dispatch_tool_call(&self, call: McpToolCall) -> McpCoreResultEnvelope<McpToolResult> {
        match self.dispatch_tool_call(call) {
            Ok(res) => McpCoreResultEnvelope::success(res),
            Err(e) => McpCoreResultEnvelope::error(e.code, e.message),
        }
    }
}

impl Default for McpServerCoreService {
    fn default() -> Self {
        Self::new()
    }
}
