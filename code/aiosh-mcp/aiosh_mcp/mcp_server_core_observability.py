"""AI Control Plane MCP Server Core Observability Subsystem (T-03135 scaffold / T-03136 impl).

Defines telemetry data models, operational metrics aggregation, health status determination,
and observability services in compliance with SPEC-MCP-SERVER-CORE-OBSERVABILITY and PoR Invariant I-2.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class HealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class McpCoreMetricsSnapshot:
    generated_at_utc: str
    uptime_seconds: float
    total_tools_registered: int
    active_sessions_count: int
    max_sessions_capacity: int
    capacity_utilization_percent: float
    total_dispatches: int
    successful_dispatches: int
    failed_dispatches: int
    policy_denials: int
    average_dispatch_latency_ms: float
    health_status: HealthStatus

    def validate(self) -> None:
        if not (self.generated_at_utc or "").strip():
            raise ValueError("generated_at_utc cannot be empty")
        try:
            datetime.fromisoformat(self.generated_at_utc.replace("Z", "+00:00"))
        except Exception as e:
            raise ValueError(f"generated_at_utc must be valid ISO timestamp: {e}")

        if not (0.0 <= self.capacity_utilization_percent <= 100.0):
            raise ValueError(f"capacity_utilization_percent ({self.capacity_utilization_percent}) out of bounds [0.0, 100.0]")

        if self.total_dispatches != (self.successful_dispatches + self.failed_dispatches):
            raise ValueError(
                f"total_dispatches ({self.total_dispatches}) != successful ({self.successful_dispatches}) + failed ({self.failed_dispatches})"
            )

        if self.uptime_seconds < 0.0:
            raise ValueError(f"uptime_seconds ({self.uptime_seconds}) cannot be negative")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at_utc": self.generated_at_utc,
            "uptime_seconds": round(self.uptime_seconds, 2),
            "total_tools_registered": self.total_tools_registered,
            "active_sessions_count": self.active_sessions_count,
            "max_sessions_capacity": self.max_sessions_capacity,
            "capacity_utilization_percent": round(self.capacity_utilization_percent, 2),
            "total_dispatches": self.total_dispatches,
            "successful_dispatches": self.successful_dispatches,
            "failed_dispatches": self.failed_dispatches,
            "policy_denials": self.policy_denials,
            "average_dispatch_latency_ms": round(self.average_dispatch_latency_ms, 3),
            "health_status": self.health_status.value,
        }


class McpServerCoreObservabilityService:
    """Aggregates real-time metrics and generates point-in-time observability snapshots."""

    def __init__(self) -> None:
        self._start_time: float = time.monotonic()
        self._total_dispatches: int = 0
        self._successful_dispatches: int = 0
        self._failed_dispatches: int = 0
        self._policy_denials: int = 0
        self._total_dispatch_duration_ms: float = 0.0

    @property
    def total_dispatches(self) -> int:
        return self._total_dispatches

    def record_dispatch(self, success: bool, duration_ms: float) -> None:
        self._total_dispatches += 1
        if success:
            self._successful_dispatches += 1
        else:
            self._failed_dispatches += 1
        self._total_dispatch_duration_ms += max(0.0, duration_ms)

    def record_policy_denial(self) -> None:
        self._policy_denials += 1

    def compute_health(self, capacity_pct: float, failure_rate_pct: float) -> HealthStatus:
        if capacity_pct >= 98.0 or failure_rate_pct >= 20.0:
            return HealthStatus.CRITICAL
        if capacity_pct >= 85.0 or failure_rate_pct >= 5.0:
            return HealthStatus.DEGRADED
        return HealthStatus.HEALTHY

    def get_snapshot(
        self,
        tools_count: int = 0,
        active_sessions: int = 0,
        max_capacity: int = 64,
    ) -> McpCoreMetricsSnapshot:
        uptime = time.monotonic() - self._start_time
        safe_capacity = max(1, max_capacity)
        capacity_pct = min(100.0, (active_sessions / safe_capacity) * 100.0)

        failure_rate = (
            (self._failed_dispatches / self._total_dispatches) * 100.0
            if self._total_dispatches >= 20
            else 0.0
        )
        health = self.compute_health(capacity_pct, failure_rate)

        avg_latency = (
            self._total_dispatch_duration_ms / self._total_dispatches
            if self._total_dispatches > 0
            else 0.0
        )

        snapshot = McpCoreMetricsSnapshot(
            generated_at_utc=datetime.now(timezone.utc).isoformat(),
            uptime_seconds=uptime,
            total_tools_registered=tools_count,
            active_sessions_count=active_sessions,
            max_sessions_capacity=max_capacity,
            capacity_utilization_percent=capacity_pct,
            total_dispatches=self._total_dispatches,
            successful_dispatches=self._successful_dispatches,
            failed_dispatches=self._failed_dispatches,
            policy_denials=self._policy_denials,
            average_dispatch_latency_ms=avg_latency,
            health_status=health,
        )
        snapshot.validate()
        return snapshot


_GLOBAL_OBSERVABILITY_SERVICE = McpServerCoreObservabilityService()


def get_observability_service() -> McpServerCoreObservabilityService:
    return _GLOBAL_OBSERVABILITY_SERVICE


def register_mcp_observability_tools(mcp_app: Any) -> None:
    """Register MCP Server Core Observability diagnostic tools with FastMCP (T-03138)."""
    @mcp_app.tool()
    def aios_mcp_observability_snapshot() -> dict:
        """Capture point-in-time runtime metrics snapshot for MCP Server Core."""
        try:
            snapshot = _GLOBAL_OBSERVABILITY_SERVICE.get_snapshot(
                tools_count=len(mcp_app._tool_manager.list_tools()) if hasattr(mcp_app, "_tool_manager") else 0,
                active_sessions=1,
                max_capacity=64,
            )
            return {
                "ok": True,
                "snapshot": snapshot.to_dict(),
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

