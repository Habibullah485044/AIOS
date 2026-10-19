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

pub fn dispatch_model_cli(
    subcmd: &ModelCliSubcommand,
    endpoints: &mut Vec<ModelEndpointConfig>,
) -> ModelCliOutput {
    match subcmd {
        ModelCliSubcommand::List { provider, active_only, json } => {
            let mut filtered = endpoints.clone();
            if let Some(ref prov) = provider {
                filtered.retain(|e| {
                    let prov_str = serde_json::to_string(&e.provider).unwrap_or_default().replace('"', "");
                    prov_str.eq_ignore_ascii_case(prov)
                });
            }
            if *active_only {
                filtered.retain(|e| e.is_active);
            }
            if *json {
                let payload = json!({
                    "status": "success",
                    "ok": true,
                    "exit_code": EXIT_SUCCESS,
                    "count": filtered.len(),
                    "endpoints": filtered,
                });
                ModelCliOutput::success(serde_json::to_string(&payload).unwrap_or_default(), Some(payload))
            } else {
                let lines: Vec<String> = filtered.iter().map(|e| {
                    format!("{} [{:?}] model={} active={}", e.backend_id, e.provider, e.model_name, e.is_active)
                }).collect();
                ModelCliOutput::success(if lines.is_empty() { "No endpoints found".to_string() } else { lines.join("\n") }, None)
            }
        }
        ModelCliSubcommand::Show { backend_id, json } => {
            if let Some(cfg) = endpoints.iter().find(|e| &e.backend_id == backend_id) {
                if *json {
                    let payload = json!({
                        "status": "success",
                        "ok": true,
                        "exit_code": EXIT_SUCCESS,
                        "endpoint": cfg,
                    });
                    ModelCliOutput::success(serde_json::to_string(&payload).unwrap_or_default(), Some(payload))
                } else {
                    ModelCliOutput::success(format!("Backend: {}\nProvider: {:?}\nModel: {}\nActive: {}", cfg.backend_id, cfg.provider, cfg.model_name, cfg.is_active), None)
                }
            } else {
                ModelCliOutput::failure_with_json(EXIT_FAILURE, format!("Backend '{}' not found", backend_id), *json)
            }
        }
        ModelCliSubcommand::Health { backend_id, json } => {
            if let Some(ref id) = backend_id {
                if let Some(cfg) = endpoints.iter().find(|e| &e.backend_id == id) {
                    if *json {
                        let payload = json!({
                            "status": "success",
                            "ok": true,
                            "exit_code": EXIT_SUCCESS,
                            "data": {
                                "backend_id": id,
                                "active": cfg.is_active,
                                "adapter_available": true
                            }
                        });
                        ModelCliOutput::success(serde_json::to_string(&payload).unwrap_or_default(), Some(payload))
                    } else {
                        ModelCliOutput::success(format!("{}: active={}, adapter_ready=true", id, cfg.is_active), None)
                    }
                } else {
                    ModelCliOutput::failure_with_json(EXIT_FAILURE, format!("Unknown backend: {}", id), *json)
                }
            } else {
                let active_count = endpoints.iter().filter(|e| e.is_active).count();
                if *json {
                    let payload = json!({
                        "status": "success",
                        "ok": true,
                        "exit_code": EXIT_SUCCESS,
                        "data": {
                            "total_endpoints": endpoints.len(),
                            "active_endpoints": active_count,
                            "adapters_available": ["mock", "openai_compatible", "anthropic", "gemini", "ollama"]
                        }
                    });
                    ModelCliOutput::success(serde_json::to_string(&payload).unwrap_or_default(), Some(payload))
                } else {
                    ModelCliOutput::success(format!("Health Summary: {}/{} active endpoints.", active_count, endpoints.len()), None)
                }
            }
        }
        ModelCliSubcommand::Complete { backend_id, prompt: _, temperature: _, fallbacks: _, token, json } => {
            if token.as_ref().map_or(true, |t| t.trim().is_empty()) {
                return ModelCliOutput::failure_with_json(
                    EXIT_UNAUTHORIZED,
                    "MODSERV_ERR_UNAUTHORIZED: subcommand 'complete' requires a capability token (--token)",
                    *json,
                );
            }
            if let Some(cfg) = endpoints.iter().find(|e| &e.backend_id == backend_id) {
                let resp_payload = json!({
                    "id": "resp-mock-1",
                    "model": cfg.model_name,
                    "content": "Mock completion response",
                    "finish_reason": "stop",
                    "latency_ms": 1.5
                });
                if *json {
                    let payload = json!({
                        "status": "success",
                        "ok": true,
                        "exit_code": EXIT_SUCCESS,
                        "response": resp_payload
                    });
                    ModelCliOutput::success(serde_json::to_string(&payload).unwrap_or_default(), Some(payload))
                } else {
                    ModelCliOutput::success(format!("[{}] Mock completion response", cfg.model_name), None)
                }
            } else {
                ModelCliOutput::failure_with_json(EXIT_FAILURE, format!("Backend '{}' not found", backend_id), *json)
            }
        }
        ModelCliSubcommand::Register { backend_id, provider, model, base_url, env, timeout, token, json } => {
            if token.as_ref().map_or(true, |t| t.trim().is_empty()) {
                return ModelCliOutput::failure_with_json(
                    EXIT_UNAUTHORIZED,
                    "MODSERV_ERR_UNAUTHORIZED: subcommand 'register' requires a capability token (--token)",
                    *json,
                );
            }
            let prov = match provider.to_lowercase().as_str() {
                "mock" => ModelProviderType::Mock,
                "openai_compatible" => ModelProviderType::OpenaiCompatible,
                "anthropic" => ModelProviderType::Anthropic,
                "gemini" => ModelProviderType::Gemini,
                "ollama" => ModelProviderType::Ollama,
                _ => return ModelCliOutput::failure_with_json(EXIT_USAGE, format!("Invalid provider: {}", provider), *json),
            };
            let new_cfg = ModelEndpointConfig {
                backend_id: backend_id.clone(),
                provider: prov,
                model_name: model.clone(),
                base_url: base_url.clone(),
                api_key_env: env.clone(),
                timeout_ms: timeout.unwrap_or(30000),
                max_retries: 3,
                capabilities: ModelCapabilities::default(),
                is_active: true,
            };
            if let Err(e) = new_cfg.validate() {
                return ModelCliOutput::failure_with_json(EXIT_FAILURE, e, *json);
            }
            endpoints.retain(|e| e.backend_id != *backend_id);
            endpoints.push(new_cfg.clone());
            if *json {
                let payload = json!({
                    "status": "success",
                    "ok": true,
                    "exit_code": EXIT_SUCCESS,
                    "registered": new_cfg
                });
                ModelCliOutput::success(serde_json::to_string(&payload).unwrap_or_default(), Some(payload))
            } else {
                ModelCliOutput::success(format!("Successfully registered backend '{}'", backend_id), None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_endpoints() -> Vec<ModelEndpointConfig> {
        vec![
            ModelEndpointConfig {
                backend_id: "mock-default".to_string(),
                provider: ModelProviderType::Mock,
                model_name: "mock-v1".to_string(),
                base_url: None,
                api_key_env: None,
                timeout_ms: 30000,
                max_retries: 3,
                capabilities: ModelCapabilities::default(),
                is_active: true,
            },
            ModelEndpointConfig {
                backend_id: "openai-gpt4".to_string(),
                provider: ModelProviderType::OpenaiCompatible,
                model_name: "gpt-4o".to_string(),
                base_url: None,
                api_key_env: Some("OPENAI_KEY".to_string()),
                timeout_ms: 60000,
                max_retries: 2,
                capabilities: ModelCapabilities::default(),
                is_active: false,
            },
        ]
    }

    #[test]
    fn test_exit_codes_constants() {
        assert_eq!(EXIT_SUCCESS, 0);
        assert_eq!(EXIT_FAILURE, 1);
        assert_eq!(EXIT_USAGE, 2);
        assert_eq!(EXIT_UNAUTHORIZED, 3);
        assert_eq!(EXIT_TIMEOUT, 4);
    }

    #[test]
    fn test_parse_nul_byte_rejection() {
        let args = vec!["list".to_string(), "bad\0arg".to_string()];
        let res = parse_model_cli_args(&args);
        assert!(res.is_err());
        let (code, msg) = res.unwrap_err();
        assert_eq!(code, EXIT_USAGE);
        assert!(msg.contains("NUL byte"));
    }

    #[test]
    fn test_parse_subcommands_valid() {
        let args = vec!["list".to_string(), "--provider".to_string(), "mock".to_string(), "--json".to_string()];
        let cmd = parse_model_cli_args(&args).expect("valid parse");
        match cmd {
            ModelCliSubcommand::List { provider, active_only, json } => {
                assert_eq!(provider, Some("mock".to_string()));
                assert!(!active_only);
                assert!(json);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_dispatch_list_and_show() {
        let mut endpoints = sample_endpoints();
        let cmd = ModelCliSubcommand::List { provider: None, active_only: false, json: true };
        let out = dispatch_model_cli(&cmd, &mut endpoints);
        assert_eq!(out.exit_code, EXIT_SUCCESS);
        let payload = out.json_payload.expect("has payload");
        assert_eq!(payload["ok"], true);
        assert_eq!(payload["count"], 2);

        let cmd_show = ModelCliSubcommand::Show { backend_id: "mock-default".to_string(), json: true };
        let out_show = dispatch_model_cli(&cmd_show, &mut endpoints);
        assert_eq!(out_show.exit_code, EXIT_SUCCESS);

        let cmd_missing = ModelCliSubcommand::Show { backend_id: "unknown".to_string(), json: true };
        let out_missing = dispatch_model_cli(&cmd_missing, &mut endpoints);
        assert_eq!(out_missing.exit_code, EXIT_FAILURE);
    }

    #[test]
    fn test_dispatch_por_token_enforcement() {
        let mut endpoints = sample_endpoints();
        // Complete without token
        let cmd_comp_no_tok = ModelCliSubcommand::Complete {
            backend_id: "mock-default".to_string(),
            prompt: "test".to_string(),
            temperature: 0.7,
            fallbacks: vec![],
            token: None,
            json: true,
        };
        let out = dispatch_model_cli(&cmd_comp_no_tok, &mut endpoints);
        assert_eq!(out.exit_code, EXIT_UNAUTHORIZED);

        // Complete with token
        let cmd_comp_tok = ModelCliSubcommand::Complete {
            backend_id: "mock-default".to_string(),
            prompt: "test".to_string(),
            temperature: 0.7,
            fallbacks: vec![],
            token: Some("token-grant-1".to_string()),
            json: true,
        };
        let out_ok = dispatch_model_cli(&cmd_comp_tok, &mut endpoints);
        assert_eq!(out_ok.exit_code, EXIT_SUCCESS);

        // Register without token
        let cmd_reg_no_tok = ModelCliSubcommand::Register {
            backend_id: "new-b".to_string(),
            provider: "mock".to_string(),
            model: "m-1".to_string(),
            base_url: None,
            env: None,
            timeout: None,
            token: None,
            json: true,
        };
        let out_reg = dispatch_model_cli(&cmd_reg_no_tok, &mut endpoints);
        assert_eq!(out_reg.exit_code, EXIT_UNAUTHORIZED);
    }
}
