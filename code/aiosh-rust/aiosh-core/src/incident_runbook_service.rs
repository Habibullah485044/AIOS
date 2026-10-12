//! Incident Response Runbooks Core Service (IR-SVC1..IR-SVC5).
//!
//! Provides the execution state machine, parameter interpolation, step dispatch,
//! and session records for AIOS Incident Response Runbooks.

use std::collections::HashMap;
use std::fmt;
use serde::{Deserialize, Serialize};

use crate::canonical::utcnow_iso;
use crate::incident_runbook_data_model::*;

pub const RUNBOOK_ERR_SESSION_NOT_FOUND: &str = "RUNBOOK_ERR_SESSION_NOT_FOUND";
pub const RUNBOOK_ERR_INVALID_TRANSITION: &str = "RUNBOOK_ERR_INVALID_TRANSITION";
pub const RUNBOOK_ERR_MISSING_CONFIRMATION: &str = "RUNBOOK_ERR_MISSING_CONFIRMATION";
pub const RUNBOOK_ERR_MISSING_CAPABILITY: &str = "RUNBOOK_ERR_MISSING_CAPABILITY";
pub const RUNBOOK_ERR_TIMEOUT_EXCEEDED: &str = "RUNBOOK_ERR_TIMEOUT_EXCEEDED";
pub const RUNBOOK_ERR_PARAMETER_NOT_FOUND: &str = "RUNBOOK_ERR_PARAMETER_NOT_FOUND";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepExecutionStatus {
    Pending,
    Running,
    AwaitingConfirmation,
    Completed,
    Failed,
    TimedOut,
    Skipped,
}

impl StepExecutionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            StepExecutionStatus::Pending => "pending",
            StepExecutionStatus::Running => "running",
            StepExecutionStatus::AwaitingConfirmation => "awaiting_confirmation",
            StepExecutionStatus::Completed => "completed",
            StepExecutionStatus::Failed => "failed",
            StepExecutionStatus::TimedOut => "timed_out",
            StepExecutionStatus::Skipped => "skipped",
        }
    }

    pub fn parse_status(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "pending" => Some(StepExecutionStatus::Pending),
            "running" => Some(StepExecutionStatus::Running),
            "awaiting_confirmation" | "confirm" => Some(StepExecutionStatus::AwaitingConfirmation),
            "completed" | "done" => Some(StepExecutionStatus::Completed),
            "failed" | "err" => Some(StepExecutionStatus::Failed),
            "timed_out" | "timeout" => Some(StepExecutionStatus::TimedOut),
            "skipped" => Some(StepExecutionStatus::Skipped),
            _ => None,
        }
    }
}

impl fmt::Display for StepExecutionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunbookExecutionStatus {
    Pending,
    Running,
    AwaitingConfirmation,
    Completed,
    Failed,
    Aborted,
}

impl RunbookExecutionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            RunbookExecutionStatus::Pending => "pending",
            RunbookExecutionStatus::Running => "running",
            RunbookExecutionStatus::AwaitingConfirmation => "awaiting_confirmation",
            RunbookExecutionStatus::Completed => "completed",
            RunbookExecutionStatus::Failed => "failed",
            RunbookExecutionStatus::Aborted => "aborted",
        }
    }

    pub fn parse_status(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "pending" => Some(RunbookExecutionStatus::Pending),
            "running" => Some(RunbookExecutionStatus::Running),
            "awaiting_confirmation" => Some(RunbookExecutionStatus::AwaitingConfirmation),
            "completed" => Some(RunbookExecutionStatus::Completed),
            "failed" => Some(RunbookExecutionStatus::Failed),
            "aborted" => Some(RunbookExecutionStatus::Aborted),
            _ => None,
        }
    }
}

impl fmt::Display for RunbookExecutionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepExecutionRecord {
    pub step_id: String,
    pub status: StepExecutionStatus,
    pub command_rendered: String,
    pub started_at: String,
    pub completed_at: String,
    pub exit_code: Option<i32>,
    pub output: String,
    pub error_message: Option<String>,
}

impl StepExecutionRecord {
    pub fn new(step_id: &str, command_rendered: &str) -> Self {
        Self {
            step_id: step_id.to_string(),
            status: StepExecutionStatus::Pending,
            command_rendered: command_rendered.to_string(),
            started_at: String::new(),
            completed_at: String::new(),
            exit_code: None,
            output: String::new(),
            error_message: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookExecutionSession {
    pub session_id: String,
    pub runbook_id: String,
    pub incident_id: String,
    pub status: RunbookExecutionStatus,
    pub current_step_index: usize,
    pub step_records: Vec<StepExecutionRecord>,
    pub parameters: HashMap<String, String>,
    pub operator_confirmed: bool,
    pub started_at: String,
    pub completed_at: String,
}

impl RunbookExecutionSession {
    pub fn new(
        session_id: &str,
        runbook_id: &str,
        incident_id: &str,
        parameters: HashMap<String, String>,
    ) -> Self {
        Self {
            session_id: session_id.to_string(),
            runbook_id: runbook_id.to_string(),
            incident_id: incident_id.to_string(),
            status: RunbookExecutionStatus::Pending,
            current_step_index: 0,
            step_records: Vec::new(),
            parameters,
            operator_confirmed: false,
            started_at: utcnow_iso(),
            completed_at: String::new(),
        }
    }

    pub fn init_from_spec(
        spec: &RunbookSpec,
        incident_id: &str,
        parameters: HashMap<String, String>,
    ) -> Result<Self, String> {
        spec.validate()?;

        let mut step_records = Vec::with_capacity(spec.steps.len());
        for step in &spec.steps {
            let rendered = render_action_template(&step.action_template, &parameters)?;
            step_records.push(StepExecutionRecord::new(&step.id, &rendered));
        }

        let session_id = format!("SES-{}-{}", spec.id, utcnow_iso().replace(':', "-"));

        Ok(Self {
            session_id,
            runbook_id: spec.id.clone(),
            incident_id: incident_id.to_string(),
            status: RunbookExecutionStatus::Pending,
            current_step_index: 0,
            step_records,
            parameters,
            operator_confirmed: false,
            started_at: utcnow_iso(),
            completed_at: String::new(),
        })
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            RunbookExecutionStatus::Completed
                | RunbookExecutionStatus::Failed
                | RunbookExecutionStatus::Aborted
        )
    }
}

pub fn render_action_template(
    template: &str,
    parameters: &HashMap<String, String>,
) -> Result<String, String> {
    validate_action_template(template)?;

    let mut result = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '{' {
            let mut key = String::new();
            for inner in chars.by_ref() {
                if inner == '}' {
                    break;
                }
                key.push(inner);
            }
            let key_trimmed = key.trim();
            if let Some(val) = parameters.get(key_trimmed) {
                // Ensure value does not contain command injection characters
                if val.chars().any(|ch| ch == ';' || ch == '|' || ch == '&' || ch == '`' || ch == '$' || ch == '\n') {
                    return Err(format!("{}: Parameter '{}' contains forbidden shell characters", RUNBOOK_ERR_INVALID_TEMPLATE, key_trimmed));
                }
                result.push_str(val);
            } else {
                return Err(format!("{}: Missing required parameter '{}'", RUNBOOK_ERR_PARAMETER_NOT_FOUND, key_trimmed));
            }
        } else {
            result.push(c);
        }
    }

    Ok(result)
}
