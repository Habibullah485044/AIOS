//! AI Control Plane Model Backend Adapters MCP/API Surface (T-03195 scaffold / T-03196 impl).
//!
//! Exposes wire protocol routing and JSON-RPC 2.0 adapters for Model Backend Adapters
//! in compliance with SPEC-MODEL-BACKEND-ADAPTERS-MCP-API, ADR-0035 §D-2, and PoR Invariant I-2.

use serde_json::{json, Value};
use crate::model_backend_adapters_data_model::*;

pub const PROTOCOL_VERSION: &str = "2025-06-18";
pub const SERVER_NAME: &str = "aiosh-model-backend";
pub const SERVER_VERSION: &str = "0.1.0";

pub const ERR_SUCCESS: i64 = 0;
pub const ERR_INVALID_PARAMS: i64 = -32602;
pub const ERR_UNAUTHORIZED: i64 = -32003;
pub const ERR_NOT_FOUND: i64 = -32004;
pub const ERR_TIMEOUT: i64 = -32005;
pub const ERR_INTERNAL: i64 = -32603;

pub struct ModelBackendApiHandler {
    pub endpoints: Vec<ModelEndpointConfig>,
}

impl Default for ModelBackendApiHandler {
    fn default() -> Self {
        Self {
            endpoints: vec![
                ModelEndpointConfig {
                    backend_id: "mock-default".to_string(),
                    provider: ModelProviderType::Mock,
                    model_name: "mock-model-v1".to_string(),
                    base_url: None,
                    api_key_env: None,
                    timeout_ms: 30000,
                    max_retries: 3,
                    capabilities: ModelCapabilities::default(),
                    is_active: true,
                },
            ],
        }
    }
}

impl ModelBackendApiHandler {
    pub fn new(endpoints: Vec<ModelEndpointConfig>) -> Self {
        Self { endpoints }
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
        Self::make_result(
            id,
            json!({
                "status": "ok",
                "service": SERVER_NAME,
                "protocolVersion": PROTOCOL_VERSION
            }),
        )
    }

    pub fn handle_list(&self, id: Option<Value>, params: Option<&Value>) -> Value {
        let provider_filter = params.and_then(|p| p.get("provider")).and_then(|v| v.as_str());
        let active_only = params.and_then(|p| p.get("active_only")).and_then(|v| v.as_bool()).unwrap_or(false);

        let mut filtered = self.endpoints.clone();
        if let Some(prov) = provider_filter {
            filtered.retain(|e| {
                let s = serde_json::to_string(&e.provider).unwrap_or_default().replace('"', "");
                s.eq_ignore_ascii_case(prov)
            });
        }
        if active_only {
            filtered.retain(|e| e.is_active);
        }

        Self::make_result(
            id,
            json!({
                "status": "success",
                "ok": true,
                "count": filtered.len(),
                "endpoints": filtered
            }),
        )
    }

    pub fn handle_show(&self, id: Option<Value>, params: Option<&Value>) -> Value {
        let backend_id = match params.and_then(|p| p.get("backend_id")).and_then(|v| v.as_str()) {
            Some(bid) => bid,
            None => return Self::make_error(id, ERR_INVALID_PARAMS, "Missing 'backend_id' parameter"),
        };

        match self.endpoints.iter().find(|e| e.backend_id == backend_id) {
            Some(cfg) => Self::make_result(id, json!({
                "status": "success",
                "ok": true,
                "endpoint": cfg
            })),
            None => Self::make_error(id, ERR_NOT_FOUND, format!("Endpoint '{}' not found", backend_id)),
        }
    }

    pub fn handle_health(&self, id: Option<Value>, params: Option<&Value>) -> Value {
        let backend_id = params.and_then(|p| p.get("backend_id")).and_then(|v| v.as_str());
        if let Some(bid) = backend_id {
            match self.endpoints.iter().find(|e| e.backend_id == bid) {
                Some(cfg) => Self::make_result(id, json!({
                    "status": "success",
                    "ok": true,
                    "data": {
                        "backend_id": bid,
                        "active": cfg.is_active,
                        "adapter_available": true
                    }
                })),
                None => Self::make_error(id, ERR_NOT_FOUND, format!("Unknown backend '{}'", bid)),
            }
        } else {
            let active = self.endpoints.iter().filter(|e| e.is_active).count();
            Self::make_result(id, json!({
                "status": "success",
                "ok": true,
                "data": {
                    "total_endpoints": self.endpoints.len(),
                    "active_endpoints": active,
                    "adapters_available": ["mock", "openai_compatible", "anthropic", "gemini", "ollama"]
                }
            }))
        }
    }

    pub fn handle_complete(&self, id: Option<Value>, params: Option<&Value>) -> Value {
        let cap_token = params.and_then(|p| p.get("capability_token")).and_then(|v| v.as_str());
        if cap_token.map_or(true, |t| t.trim().is_empty()) {
            return Self::make_error(
                id,
                ERR_UNAUTHORIZED,
                "MODSERV_ERR_UNAUTHORIZED: 'capability_token' required for inference completion",
            );
        }

        let backend_id = match params.and_then(|p| p.get("backend_id")).and_then(|v| v.as_str()) {
            Some(b) => b,
            None => return Self::make_error(id, ERR_INVALID_PARAMS, "Missing 'backend_id' parameter"),
        };

        let prompt = match params.and_then(|p| p.get("prompt")).and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return Self::make_error(id, ERR_INVALID_PARAMS, "Missing 'prompt' parameter"),
        };

        if prompt.as_bytes().len() > 1024 * 1024 {
            return Self::make_error(id, ERR_INVALID_PARAMS, "Prompt exceeds 1 MiB limit");
        }

        match self.endpoints.iter().find(|e| e.backend_id == backend_id) {
            Some(cfg) => Self::make_result(id, json!({
                "status": "success",
                "ok": true,
                "response": {
                    "id": "resp-mock-api-1",
                    "model": cfg.model_name,
                    "content": "Mock API completion response",
                    "finish_reason": "stop",
                    "latency_ms": 1.2
                }
            })),
            None => Self::make_error(id, ERR_NOT_FOUND, format!("Backend '{}' not found", backend_id)),
        }
    }

    pub fn handle_register(&mut self, id: Option<Value>, params: Option<&Value>) -> Value {
        let cap_token = params.and_then(|p| p.get("capability_token")).and_then(|v| v.as_str());
        if cap_token.map_or(true, |t| t.trim().is_empty()) {
            return Self::make_error(
                id,
                ERR_UNAUTHORIZED,
                "MODSERV_ERR_UNAUTHORIZED: 'capability_token' required for endpoint registration",
            );
        }

        let backend_id = match params.and_then(|p| p.get("backend_id")).and_then(|v| v.as_str()) {
            Some(b) => b,
            None => return Self::make_error(id, ERR_INVALID_PARAMS, "Missing 'backend_id'"),
        };
        let prov_str = match params.and_then(|p| p.get("provider")).and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return Self::make_error(id, ERR_INVALID_PARAMS, "Missing 'provider'"),
        };
        let model_name = match params.and_then(|p| p.get("model_name")).and_then(|v| v.as_str()) {
            Some(m) => m,
            None => return Self::make_error(id, ERR_INVALID_PARAMS, "Missing 'model_name'"),
        };

        let prov = match prov_str.to_lowercase().as_str() {
            "mock" => ModelProviderType::Mock,
            "openai_compatible" => ModelProviderType::OpenaiCompatible,
            "anthropic" => ModelProviderType::Anthropic,
            "gemini" => ModelProviderType::Gemini,
            "ollama" => ModelProviderType::Ollama,
            _ => return Self::make_error(id, ERR_INVALID_PARAMS, format!("Invalid provider: {}", prov_str)),
        };

        let new_cfg = ModelEndpointConfig {
            backend_id: backend_id.to_string(),
            provider: prov,
            model_name: model_name.to_string(),
            base_url: params.and_then(|p| p.get("base_url")).and_then(|v| v.as_str()).map(|s| s.to_string()),
            api_key_env: params.and_then(|p| p.get("api_key_env")).and_then(|v| v.as_str()).map(|s| s.to_string()),
            timeout_ms: params.and_then(|p| p.get("timeout_ms")).and_then(|v| v.as_u64()).unwrap_or(30000),
            max_retries: 3,
            capabilities: ModelCapabilities::default(),
            is_active: true,
        };

        if let Err(e) = new_cfg.validate() {
            return Self::make_error(id, ERR_INVALID_PARAMS, e);
        }

        self.endpoints.retain(|e| e.backend_id != backend_id);
        self.endpoints.push(new_cfg.clone());

        Self::make_result(id, json!({
            "status": "success",
            "ok": true,
            "registered": new_cfg
        }))
    }

    pub fn handle_request(&mut self, body: &Value) -> Value {
        let req_id = body.get("id").cloned();
        let method = match body.get("method").and_then(|v| v.as_str()) {
            Some(m) => m,
            None => return Self::make_error(req_id, ERR_INVALID_PARAMS, "Missing 'method' field"),
        };
        let params = body.get("params");

        match method {
            "ping" | "model_backend_ping" => self.handle_ping(req_id),
            "tools/list" | "model_backend_list" => self.handle_list(req_id, params),
            "model_backend_show" => self.handle_show(req_id, params),
            "model_backend_health" => self.handle_health(req_id, params),
            "model_backend_complete" => self.handle_complete(req_id, params),
            "model_backend_register" => self.handle_register(req_id, params),
            other => Self::make_error(req_id, -32601, format!("Method '{}' not found", other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_api_ping() {
        let handler = ModelBackendApiHandler::default();
        let res = handler.handle_ping(Some(json!(1)));
        assert_eq!(res["jsonrpc"], "2.0");
        assert_eq!(res["result"]["status"], "ok");
    }

    #[test]
    fn test_rust_api_list_and_show() {
        let handler = ModelBackendApiHandler::default();
        let res_list = handler.handle_list(Some(json!(2)), None);
        assert_eq!(res_list["result"]["ok"], true);
        assert_eq!(res_list["result"]["count"], 1);

        let res_show = handler.handle_show(Some(json!(3)), Some(&json!({"backend_id": "mock-default"})));
        assert_eq!(res_show["result"]["ok"], true);
        assert_eq!(res_show["result"]["endpoint"]["backend_id"], "mock-default");

        let res_nf = handler.handle_show(Some(json!(4)), Some(&json!({"backend_id": "missing"})));
        assert_eq!(res_nf["error"]["code"], ERR_NOT_FOUND);
    }

    #[test]
    fn test_rust_api_por_token_gating() {
        let mut handler = ModelBackendApiHandler::default();
        // Complete without token rejected
        let res_comp_no = handler.handle_complete(
            Some(json!(5)),
            Some(&json!({"backend_id": "mock-default", "prompt": "hi"})),
        );
        assert_eq!(res_comp_no["error"]["code"], ERR_UNAUTHORIZED);

        // Complete with token succeeds
        let res_comp_ok = handler.handle_complete(
            Some(json!(6)),
            Some(&json!({
                "backend_id": "mock-default",
                "prompt": "hi",
                "capability_token": "grant-token-1"
            })),
        );
        assert_eq!(res_comp_ok["result"]["ok"], true);

        // Register without token rejected
        let res_reg_no = handler.handle_register(
            Some(json!(7)),
            Some(&json!({"backend_id": "new-1", "provider": "mock", "model_name": "m"})),
        );
        assert_eq!(res_reg_no["error"]["code"], ERR_UNAUTHORIZED);

        // Register with token succeeds
        let res_reg_ok = handler.handle_register(
            Some(json!(8)),
            Some(&json!({
                "backend_id": "new-1",
                "provider": "mock",
                "model_name": "m",
                "capability_token": "grant-token-1"
            })),
        );
        assert_eq!(res_reg_ok["result"]["ok"], true);
    }

    #[test]
    fn test_rust_api_request_dispatch() {
        let mut handler = ModelBackendApiHandler::default();
        let body = json!({"id": 10, "method": "model_backend_ping"});
        let res = handler.handle_request(&body);
        assert_eq!(res["result"]["status"], "ok");

        let body_unk = json!({"id": 11, "method": "invalid_method"});
        let res_unk = handler.handle_request(&body_unk);
        assert_eq!(res_unk["error"]["code"], -32601);
    }
}
