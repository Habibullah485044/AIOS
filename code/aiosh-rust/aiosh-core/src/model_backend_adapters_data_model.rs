//! AI Control Plane Model Backend Adapters Data Model (MODADAPT-INV1..MODADAPT-INV5).

use serde::{Deserialize, Serialize};

pub const MODADAPT_ERR_INVALID_ROLE: &str = "MODADAPT_ERR_INVALID_ROLE";
pub const MODADAPT_ERR_BOUNDS: &str = "MODADAPT_ERR_BOUNDS";
pub const MODADAPT_ERR_SECRET_LEAK: &str = "MODADAPT_ERR_SECRET_LEAK";

pub const MIN_TIMEOUT_MS: u64 = 1000;
pub const MAX_TIMEOUT_MS: u64 = 300000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelProviderType {
    OpenaiCompatible,
    Anthropic,
    Gemini,
    Ollama,
    Mock,
}

pub fn validate_role(role: &str) -> Result<String, String> {
    let cleaned = role.trim().to_lowercase();
    match cleaned.as_str() {
        "system" | "user" | "assistant" | "tool" => Ok(cleaned),
        _ => Err(format!(
            "{}: role '{}' not valid (allowed: system, user, assistant, tool)",
            MODADAPT_ERR_INVALID_ROLE, cleaned
        )),
    }
}

pub fn validate_temperature(temp: f64) -> Result<f64, String> {
    if (0.0..=2.0).contains(&temp) {
        Ok(temp)
    } else {
        Err(format!(
            "{}: temperature ({}) out of bounds [0.0, 2.0]",
            MODADAPT_ERR_BOUNDS, temp
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCapabilities {
    pub streaming: bool,
    pub tool_calling: bool,
    pub vision: bool,
    pub json_mode: bool,
    pub max_context_window: u64,
    pub max_output_tokens: u64,
}

impl Default for ModelCapabilities {
    fn default() -> Self {
        Self {
            streaming: true,
            tool_calling: true,
            vision: false,
            json_mode: true,
            max_context_window: 128000,
            max_output_tokens: 4096,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelEndpointConfig {
    pub backend_id: String,
    pub provider: ModelProviderType,
    pub model_name: String,
    pub base_url: Option<String>,
    pub api_key_env: Option<String>,
    pub timeout_ms: u64,
    pub max_retries: u32,
    pub capabilities: ModelCapabilities,
    pub is_active: bool,
}

impl ModelEndpointConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.backend_id.trim().is_empty() {
            return Err(format!("{}: backend_id must be non-empty", MODADAPT_ERR_BOUNDS));
        }
        if self.model_name.trim().is_empty() {
            return Err(format!("{}: model_name must be non-empty", MODADAPT_ERR_BOUNDS));
        }
        if self.timeout_ms < MIN_TIMEOUT_MS || self.timeout_ms > MAX_TIMEOUT_MS {
            return Err(format!(
                "{}: timeout_ms ({}) out of bounds [{}, {}]",
                MODADAPT_ERR_BOUNDS, self.timeout_ms, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS
            ));
        }
        if self.max_retries > 10 {
            return Err(format!(
                "{}: max_retries ({}) out of bounds [0, 10]",
                MODADAPT_ERR_BOUNDS, self.max_retries
            ));
        }
        if let Some(ref env_name) = self.api_key_env {
            let trimmed = env_name.trim();
            if trimmed.starts_with("sk-") || trimmed.starts_with("ghp_") || trimmed.len() > 64 {
                return Err(format!(
                    "{}: api_key_env appears to be plaintext secret rather than env var name",
                    MODADAPT_ERR_SECRET_LEAK
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelMessage {
    pub role: String,
    pub content: String,
    pub name: Option<String>,
    pub tool_call_id: Option<String>,
}

impl ModelMessage {
    pub fn new(role: &str, content: &str) -> Result<Self, String> {
        let valid_role = validate_role(role)?;
        Ok(Self {
            role: valid_role,
            content: content.to_string(),
            name: None,
            tool_call_id: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

impl ModelUsage {
    pub fn new(prompt: u64, completion: u64) -> Self {
        Self {
            prompt_tokens: prompt,
            completion_tokens: completion,
            total_tokens: prompt + completion,
        }
    }

    pub fn validate_invariants(&self) -> Result<(), String> {
        if self.total_tokens != (self.prompt_tokens + self.completion_tokens) {
            return Err(format!(
                "MODADAPT-INV2 violated: total_tokens ({}) != prompt ({}) + completion ({})",
                self.total_tokens, self.prompt_tokens, self.completion_tokens
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelRequest {
    pub model_id: String,
    pub messages: Vec<ModelMessage>,
    pub temperature: f64,
    pub max_tokens: Option<u64>,
    pub stream: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelResponse {
    pub id: String,
    pub model: String,
    pub content: String,
    pub usage: Option<ModelUsage>,
    pub finish_reason: String,
    pub latency_ms: f64,
}
