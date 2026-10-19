//! AI Control Plane Model Backend Adapters Core Service (MODSERV-INV1..MODSERV-INV5).

use std::time::Instant;
use serde::{Deserialize, Serialize};

use crate::model_backend_adapters_data_model::{
    ModelEndpointConfig, ModelRequest, ModelResponse, ModelUsage,
};

pub const MODSERV_ERR_UNKNOWN_BACKEND: &str = "MODSERV_ERR_UNKNOWN_BACKEND";
pub const MODSERV_ERR_TIMEOUT: &str = "MODSERV_ERR_TIMEOUT";
pub const MODSERV_ERR_RATE_LIMIT: &str = "MODSERV_ERR_RATE_LIMIT";
pub const MODSERV_ERR_AUTH: &str = "MODSERV_ERR_AUTH";
pub const MODSERV_ERR_UNAVAILABLE: &str = "MODSERV_ERR_UNAVAILABLE";
pub const MODSERV_ERR_FALLBACK_EXHAUSTED: &str = "MODSERV_ERR_FALLBACK_EXHAUSTED";
pub const MODSERV_ERR_UNSUPPORTED_PROVIDER: &str = "MODSERV_ERR_UNSUPPORTED_PROVIDER";
pub const MODSERV_ERR_INVALID_PAYLOAD: &str = "MODSERV_ERR_INVALID_PAYLOAD";

pub const MAX_FALLBACK_DEPTH: usize = 5;
pub const MAX_REQUEST_MESSAGES: usize = 100;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelServiceHealth {
    pub total_endpoints: usize,
    pub active_endpoints: usize,
    pub adapters_available: Vec<String>,
}

pub struct MockModelAdapter {
    pub default_reply: String,
    pub simulated_latency_ms: f64,
}

impl Default for MockModelAdapter {
    fn default() -> Self {
        Self {
            default_reply: "Mock execution successful".to_string(),
            simulated_latency_ms: 2.0,
        }
    }
}

impl MockModelAdapter {
    pub fn complete(&self, config: &ModelEndpointConfig, request: &ModelRequest) -> Result<ModelResponse, String> {
        let start = Instant::now();
        let prompt_chars: usize = request.messages.iter().map(|m| m.content.len()).sum();
        let prompt_tokens = (prompt_chars / 4).max(1) as u64;
        let completion_tokens = (self.default_reply.len() / 4).max(1) as u64;

        let usage = ModelUsage::new(prompt_tokens, completion_tokens);
        let elapsed = start.elapsed().as_secs_f64() * 1000.0 + self.simulated_latency_ms;

        Ok(ModelResponse {
            id: format!("resp-mock-{}", chrono::Utc::now().timestamp_micros()),
            model: config.model_name.clone(),
            content: self.default_reply.clone(),
            usage: Some(usage),
            finish_reason: "stop".to_string(),
            latency_ms: elapsed,
        })
    }
}
