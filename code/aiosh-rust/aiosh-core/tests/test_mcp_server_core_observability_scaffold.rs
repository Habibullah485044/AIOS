//! Scaffold tests for MCP Server Core Observability Subsystem (T-03135).

use aiosh_core::mcp_server_core_observability::{
    HealthStatus, McpCoreMetricsSnapshot, McpServerCoreObservabilityService,
};

#[test]
fn test_observability_scaffold_types() {
    assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
    assert_ne!(HealthStatus::Healthy, HealthStatus::Critical);
}

#[test]
fn test_observability_scaffold_service() {
    let service = McpServerCoreObservabilityService::new();
    assert_eq!(service.total_dispatches(), 0);

    let snapshot = service.get_snapshot(10, 2, 64);
    assert_eq!(snapshot.total_tools_registered, 10);
    assert_eq!(snapshot.active_sessions_count, 2);
    assert_eq!(snapshot.health_status, HealthStatus::Healthy);
}
