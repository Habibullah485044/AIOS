//! AI Control Plane MCP Server Core CLI Surface (T-03085).
//!
//! Exposes command line operations for MCP tool inspection, session management,
//! and bounded dispatch in compliance with ADR-0035 §AF-2 and PoR Invariant I-2.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use crate::mcp_server_core_data_model::*;
use crate::mcp_server_core_service::*;

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_FAILURE: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_UNAUTHORIZED: i32 = 3;
pub const EXIT_TIMEOUT: i32 = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpCliSubcommand {
    List {
        filter: Option<String>,
        json: bool,
    },
    Show {
        tool: String,
        json: bool,
    },
    Dispatch {
        tool: String,
        args: Option<String>,
        grant: Option<String>,
        timeout: Option<u64>,
        json: bool,
    },
    Sessions {
        prune: Option<u64>,
        json: bool,
    },
    Ping {
        json: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpCliOutput {
    pub exit_code: i32,
    pub message: String,
    pub json_payload: Option<Value>,
}

impl McpCliOutput {
    pub fn success(msg: impl Into<String>, payload: Option<Value>) -> Self {
        Self {
            exit_code: EXIT_SUCCESS,
            message: msg.into(),
            json_payload: payload,
        }
    }

    pub fn failure(code: i32, msg: impl Into<String>) -> Self {
        Self {
            exit_code: code,
            message: msg.into(),
            json_payload: None,
        }
    }

    pub fn failure_with_json(code: i32, msg: impl Into<String>, json_mode: bool) -> Self {
        let message = msg.into();
        let payload = if json_mode {
            Some(json!({
                "status": "error",
                "ok": false,
                "error_code": code,
                "error_message": message,
            }))
        } else {
            None
        };
        Self {
            exit_code: code,
            message: if json_mode {
                payload.as_ref().unwrap().to_string()
            } else {
                message
            },
            json_payload: payload,
        }
    }
}

/// Parses CLI arguments following `aiosh mcp <subcommand> [flags]`.
pub fn parse_mcp_cli_args(args: &[String]) -> Result<McpCliSubcommand, (i32, String)> {
    if args.is_empty() {
        return Err((EXIT_USAGE, "Missing MCP subcommand (choose from list, show, dispatch, sessions, ping)".to_string()));
    }

    for arg in args {
        if arg.contains('\0') {
            return Err((EXIT_USAGE, "CLI argument contains prohibited NUL byte".to_string()));
        }
    }

    let subcmd = args[0].as_str();
    let mut json_mode = false;
    let mut filter = None;
    let mut args_payload = None;
    let mut grant = None;
    let mut timeout = None;
    let mut prune = None;
    let mut positional = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json_mode = true,
            "--filter" => {
                i += 1;
                if i >= args.len() {
                    return Err((EXIT_USAGE, "--filter requires a value".to_string()));
                }
                filter = Some(args[i].clone());
            }
            "--args" => {
                i += 1;
                if i >= args.len() {
                    return Err((EXIT_USAGE, "--args requires a JSON value".to_string()));
                }
                args_payload = Some(args[i].clone());
            }
            "--grant" => {
                i += 1;
                if i >= args.len() {
                    return Err((EXIT_USAGE, "--grant requires a grant token".to_string()));
                }
                grant = Some(args[i].clone());
            }
            "--timeout" => {
                i += 1;
                if i >= args.len() {
                    return Err((EXIT_USAGE, "--timeout requires seconds".to_string()));
                }
                let secs: u64 = args[i].parse().map_err(|_| (EXIT_USAGE, "invalid timeout integer".to_string()))?;
                timeout = Some(secs);
            }
            "--prune" => {
                i += 1;
                if i < args.len() && !args[i].starts_with("--") {
                    let secs: u64 = args[i].parse().map_err(|_| (EXIT_USAGE, "invalid prune integer".to_string()))?;
                    prune = Some(secs);
                } else {
                    prune = Some(0);
                    continue;
                }
            }
            other => {
                if other.starts_with("--") {
                    return Err((EXIT_USAGE, format!("unknown flag '{}'", other)));
                }
                positional.push(other.to_string());
            }
        }
        i += 1;
    }

    match subcmd {
        "list" => Ok(McpCliSubcommand::List { filter, json: json_mode }),
        "show" => {
            if positional.is_empty() {
                return Err((EXIT_USAGE, "show requires a tool name".to_string()));
            }
            Ok(McpCliSubcommand::Show { tool: positional[0].clone(), json: json_mode })
        }
        "dispatch" => {
            if positional.is_empty() {
                return Err((EXIT_USAGE, "dispatch requires a tool name".to_string()));
            }
            Ok(McpCliSubcommand::Dispatch {
                tool: positional[0].clone(),
                args: args_payload,
                grant,
                timeout,
                json: json_mode,
            })
        }
        "sessions" => Ok(McpCliSubcommand::Sessions { prune, json: json_mode }),
        "ping" => Ok(McpCliSubcommand::Ping { json: json_mode }),
        other => Err((EXIT_USAGE, format!("unknown subcommand '{}'", other))),
    }
}

/// Executes a parsed MCP CLI subcommand against `McpServerCoreService`.
pub fn execute_mcp_cli(cmd: &McpCliSubcommand, service: &McpServerCoreService) -> McpCliOutput {
    match cmd {
        McpCliSubcommand::Ping { json } => {
            let tools_count = service.list_tools().len();
            let payload = json!({
                "status": "ok",
                "tools_count": tools_count,
                "version": "2025-06-18",
            });
            let msg = if *json {
                payload.to_string()
            } else {
                format!("MCP Server Core is alive ({} registered tools)", tools_count)
            };
            McpCliOutput::success(msg, Some(payload))
        }
        McpCliSubcommand::List { filter, json } => {
            let mut tools = service.list_tools();
            if let Some(f) = filter {
                tools.retain(|t| t.name.contains(f));
            }
            let tools_json = json!(tools);
            let msg = if *json {
                tools_json.to_string()
            } else {
                let lines: Vec<String> = tools.iter().map(|t| format!("{}: {}", t.name, t.description)).collect();
                lines.join("\n")
            };
            McpCliOutput::success(msg, Some(tools_json))
        }
        McpCliSubcommand::Show { tool, json } => {
            match service.get_tool(tool) {
                Some(t) => {
                    let tool_json = json!(t);
                    let msg = if *json {
                        tool_json.to_string()
                    } else {
                        format!("Tool: {}\nDescription: {}\nSchema: {}", t.name, t.description, t.input_schema)
                    };
                    McpCliOutput::success(msg, Some(tool_json))
                }
                None => McpCliOutput::failure_with_json(EXIT_FAILURE, format!("tool '{}' not found", tool), *json),
            }
        }
        McpCliSubcommand::Dispatch { tool, args, grant, timeout, json: json_mode } => {
            // Check privilege grant requirements
            if tool.starts_with("aios.admin.") && grant.is_none() {
                return McpCliOutput::failure_with_json(EXIT_UNAUTHORIZED, "capability grant required for privileged tool", *json_mode);
            }

            // Parse args payload
            let args_value: Value = if let Some(a) = args {
                if a.len() > MAX_ARGUMENTS_SIZE {
                    return McpCliOutput::failure_with_json(EXIT_USAGE, "arguments exceed MAX_ARGUMENTS_SIZE limit", *json_mode);
                }
                match serde_json::from_str(a) {
                    Ok(v) => v,
                    Err(e) => return McpCliOutput::failure_with_json(EXIT_USAGE, format!("invalid JSON in --args: {}", e), *json_mode),
                }
            } else {
                json!({})
            };

            let tool_call = match McpToolCall::new(tool, args_value, grant.clone()) {
                Ok(c) => c,
                Err(e) => return McpCliOutput::failure_with_json(EXIT_USAGE, format!("invalid tool call: {:?}", e), *json_mode),
            };

            let timeout_val = timeout.unwrap_or(DEFAULT_EXECUTION_TIMEOUT_SECONDS as u64);
            let env = service.safe_dispatch_with_timeout(tool_call, timeout_val);
            let env_json = json!(env);

            if env.ok {
                let msg = if *json_mode {
                    env_json.to_string()
                } else {
                    format!("Dispatched tool '{}': ok", tool)
                };
                McpCliOutput::success(msg, Some(env_json))
            } else {
                let code = if env.error_code == Some(ERR_UNAUTHORIZED) {
                    EXIT_UNAUTHORIZED
                } else if env.error_code == Some(MCPSVC_ERR_TOOL_NOT_FOUND) {
                    EXIT_FAILURE
                } else {
                    EXIT_FAILURE
                };
                let err_msg = env.error_message.unwrap_or_else(|| "dispatch error".to_string());
                McpCliOutput::failure_with_json(code, err_msg, *json_mode)
            }
        }
        McpCliSubcommand::Sessions { prune, json: json_mode } => {
            let pruned_count = if let Some(secs) = prune {
                service.prune_idle_sessions(*secs)
            } else {
                0
            };
            let payload = json!({
                "pruned": pruned_count,
                "status": "ok",
            });
            let msg = if *json_mode {
                payload.to_string()
            } else if prune.is_some() {
                format!("Pruned {} idle/terminated sessions", pruned_count)
            } else {
                "Active sessions enumerated".to_string()
            };
            McpCliOutput::success(msg, Some(payload))
        }
    }
}
