//! AI Control Plane Model Backend Adapters CLI Surface (T-03185 Scaffold / T-03186 Impl).
//!
//! Exposes command line operations for model adapter inspection, endpoint health,
//! completion dispatch, and dynamic registration in compliance with ADR-0035 §AF-2
//! and PoR Invariant I-2.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[allow(unused_imports)]
use crate::model_backend_adapters_data_model::*;
#[allow(unused_imports)]
use crate::model_backend_adapters_service::*;

pub const EXIT_SUCCESS: i32 = 0;
pub const EXIT_FAILURE: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_UNAUTHORIZED: i32 = 3;
pub const EXIT_TIMEOUT: i32 = 4;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ModelCliSubcommand {
    List {
        provider: Option<String>,
        active_only: bool,
        json: bool,
    },
    Show {
        backend_id: String,
        json: bool,
    },
    Health {
        backend_id: Option<String>,
        json: bool,
    },
    Complete {
        backend_id: String,
        prompt: String,
        temperature: f32,
        fallbacks: Vec<String>,
        token: Option<String>,
        json: bool,
    },
    Register {
        backend_id: String,
        provider: String,
        model: String,
        base_url: Option<String>,
        env: Option<String>,
        timeout: Option<u64>,
        token: Option<String>,
        json: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelCliOutput {
    pub exit_code: i32,
    pub message: String,
    pub json_payload: Option<Value>,
}

impl ModelCliOutput {
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
        let text = msg.into();
        if json_mode {
            let payload = json!({
                "status": "error",
                "ok": false,
                "exit_code": code,
                "error_message": text
            });
            Self {
                exit_code: code,
                message: serde_json::to_string(&payload).unwrap_or_default(),
                json_payload: Some(payload),
            }
        } else {
            Self {
                exit_code: code,
                message: text,
                json_payload: None,
            }
        }
    }
}

pub fn parse_model_cli_args(args: &[String]) -> Result<ModelCliSubcommand, (i32, String)> {
    if args.is_empty() {
        return Err((
            EXIT_USAGE,
            "Missing model subcommand (choose from list, show, health, complete, register)".to_string(),
        ));
    }

    for arg in args {
        if arg.contains('\0') {
            return Err((EXIT_USAGE, "CLI argument contains prohibited NUL byte".to_string()));
        }
    }

    let subcmd = args[0].as_str();
    let mut json = false;
    let mut provider: Option<String> = None;
    let mut active_only = false;
    let mut prompt: Option<String> = None;
    let mut temperature: f32 = 0.7;
    let mut fallbacks = Vec::new();
    let mut token: Option<String> = None;
    let mut model: Option<String> = None;
    let mut base_url: Option<String> = None;
    let mut env: Option<String> = None;
    let mut timeout: Option<u64> = None;
    let mut positional = Vec::new();

    let mut i = 1;
    while i < args.len() {
        let flag = args[i].as_str();
        match flag {
            "--json" => json = true,
            "--active-only" => active_only = true,
            "--provider" => {
                i += 1;
                if i >= args.len() {
                    return Err((EXIT_USAGE, "--provider requires a value".to_string()));
                }
                provider = Some(args[i].clone());
            }
            "--prompt" => {
                i += 1;
                if i >= args.len() {
                    return Err((EXIT_USAGE, "--prompt requires text".to_string()));
                }
                prompt = Some(args[i].clone());
            }
            "--temperature" => {
                i += 1;
                if i >= args.len() {
                    return Err((EXIT_USAGE, "--temperature requires a float".to_string()));
                }
                temperature = args[i].parse::<f32>().map_err(|_| (EXIT_USAGE, format!("Invalid temperature: {}", args[i])))?;
            }
            "--fallback" => {
                i += 1;
                if i >= args.len() {
                    return Err((EXIT_USAGE, "--fallback requires a backend id".to_string()));
                }
                fallbacks.push(args[i].clone());
            }
            "--token" => {
                i += 1;
                if i >= args.len() {
                    return Err((EXIT_USAGE, "--token requires a token value".to_string()));
                }
                token = Some(args[i].clone());
            }
            "--model" => {
                i += 1;
                if i >= args.len() {
                    return Err((EXIT_USAGE, "--model requires a model name".to_string()));
                }
                model = Some(args[i].clone());
            }
            "--base-url" => {
                i += 1;
                if i >= args.len() {
                    return Err((EXIT_USAGE, "--base-url requires a URL".to_string()));
                }
                base_url = Some(args[i].clone());
            }
            "--env" => {
                i += 1;
                if i >= args.len() {
                    return Err((EXIT_USAGE, "--env requires an env var name".to_string()));
                }
                env = Some(args[i].clone());
            }
            "--timeout" => {
                i += 1;
                if i >= args.len() {
                    return Err((EXIT_USAGE, "--timeout requires milliseconds".to_string()));
                }
                timeout = Some(args[i].parse::<u64>().map_err(|_| (EXIT_USAGE, format!("Invalid timeout: {}", args[i])))?);
            }
            other if other.starts_with('-') => {
                return Err((EXIT_USAGE, format!("Unknown option '{}'", other)));
            }
            pos => positional.push(pos.to_string()),
        }
        i += 1;
    }

    match subcmd {
        "list" => Ok(ModelCliSubcommand::List {
            provider,
            active_only,
            json,
        }),
        "show" => {
            if positional.is_empty() {
                return Err((EXIT_USAGE, "Missing backend_id argument".to_string()));
            }
            Ok(ModelCliSubcommand::Show {
                backend_id: positional[0].clone(),
                json,
            })
        }
        "health" => {
            let backend_id = positional.first().cloned();
            Ok(ModelCliSubcommand::Health { backend_id, json })
        }
        "complete" => {
            if positional.is_empty() {
                return Err((EXIT_USAGE, "Missing backend_id argument".to_string()));
            }
            let p = prompt.ok_or_else(|| (EXIT_USAGE, "Missing --prompt argument".to_string()))?;
            Ok(ModelCliSubcommand::Complete {
                backend_id: positional[0].clone(),
                prompt: p,
                temperature,
                fallbacks,
                token,
                json,
            })
        }
        "register" => {
            if positional.is_empty() {
                return Err((EXIT_USAGE, "Missing backend_id argument".to_string()));
            }
            let prov = provider.ok_or_else(|| (EXIT_USAGE, "--provider is required".to_string()))?;
            let mdl = model.ok_or_else(|| (EXIT_USAGE, "--model is required".to_string()))?;
            Ok(ModelCliSubcommand::Register {
                backend_id: positional[0].clone(),
                provider: prov,
                model: mdl,
                base_url,
                env,
                timeout,
                token,
                json,
            })
        }
        other => Err((EXIT_USAGE, format!("Unknown subcommand '{}'", other))),
    }
}
