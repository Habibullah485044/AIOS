//! AI Control Plane MCP Server Core Observability Subsystem (T-03135 scaffold / T-03136 impl).
//!
//! Defines telemetry data models, operational metrics aggregation, health status determination,
//! and observability services in compliance with SPEC-MCP-SERVER-CORE-OBSERVABILITY and PoR Invariant I-2.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpCoreMetricsSnapshot {
    pub generated_at_utc: String,
    pub uptime_seconds: f64,
    pub total_tools_registered: usize,
    pub active_sessions_count: usize,
    pub max_sessions_capacity: usize,
    pub capacity_utilization_percent: f64,
    pub total_dispatches: u64,
    pub successful_dispatches: u64,
    pub failed_dispatches: u64,
    pub policy_denials: u64,
    pub average_dispatch_latency_ms: f64,
    pub health_status: HealthStatus,
}

#[derive(Debug)]
pub struct McpServerCoreObservabilityService {
    start_time: Instant,
    total_dispatches: u64,
    successful_dispatches: u64,
    failed_dispatches: u64,
    policy_denials: u64,
    total_dispatch_duration_ms: f64,
}

impl Default for McpServerCoreObservabilityService {
    fn default() -> Self {
        Self::new()
    }
}

impl McpServerCoreObservabilityService {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_dispatches: 0,
            successful_dispatches: 0,
            failed_dispatches: 0,
            policy_denials: 0,
            total_dispatch_duration_ms: 0.0,
        }
    }

    pub fn total_dispatches(&self) -> u64 {
        self.total_dispatches
    }

    pub fn record_dispatch(&mut self, success: bool, duration_ms: f64) {
        self.total_dispatches += 1;
        if success {
            self.successful_dispatches += 1;
        } else {
            self.failed_dispatches += 1;
        }
        if duration_ms > 0.0 {
            self.total_dispatch_duration_ms += duration_ms;
        }
    }

    pub fn record_policy_denial(&mut self) {
        self.policy_denials += 1;
    }

    pub fn compute_health(capacity_pct: f64, failure_rate_pct: f64) -> HealthStatus {
        if capacity_pct >= 98.0 || failure_rate_pct >= 20.0 {
            HealthStatus::Critical
        } else if capacity_pct >= 85.0 || failure_rate_pct >= 5.0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }

    pub fn get_snapshot(
        &self,
        tools_count: usize,
        active_sessions: usize,
        max_capacity: usize,
    ) -> McpCoreMetricsSnapshot {
        let uptime = self.start_time.elapsed().as_secs_f64();
        let safe_capacity = if max_capacity == 0 { 1 } else { max_capacity };
        let capacity_pct = ((active_sessions as f64 / safe_capacity as f64) * 100.0).min(100.0);

        let failure_rate = if self.total_dispatches >= 20 {
            (self.failed_dispatches as f64 / self.total_dispatches as f64) * 100.0
        } else {
            0.0
        };

        let health = Self::compute_health(capacity_pct, failure_rate);

        let avg_latency = if self.total_dispatches > 0 {
            self.total_dispatch_duration_ms / self.total_dispatches as f64
        } else {
            0.0
        };

        McpCoreMetricsSnapshot {
            generated_at_utc: Utc::now().to_rfc3339(),
            uptime_seconds: uptime,
            total_tools_registered: tools_count,
            active_sessions_count: active_sessions,
            max_sessions_capacity: max_capacity,
            capacity_utilization_percent: capacity_pct,
            total_dispatches: self.total_dispatches,
            successful_dispatches: self.successful_dispatches,
            failed_dispatches: self.failed_dispatches,
            policy_denials: self.policy_denials,
            average_dispatch_latency_ms: avg_latency,
            health_status: health,
        }
    }
}
