"""AI Control Plane Model Backend Adapters Observability Subsystem (T-03235 scaffold / T-03236 impl / T-03238 integration).

Defines telemetry data models, operational metrics aggregation, health status determination,
and observability services in compliance with SPEC-MODEL-BACKEND-ADAPTERS-OBSERVABILITY and PoR Invariant I-2.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

MAX_TELEMETRY_TEXT_LEN: int = 256
_FORBIDDEN_CHARS = {"\u200b", "\u200c", "\u200d", "\ufeff", "\x00"}


def sanitize_telemetry_text(s: str) -> str:
    """Sanitizes telemetry text by filtering control characters, zero-width chars, and enforcing bounds."""
    if not s:
        return ""
    filtered = "".join(c for c in s if not (ord(c) < 32 or ord(c) == 127 or c in _FORBIDDEN_CHARS))
    return filtered[:MAX_TELEMETRY_TEXT_LEN].strip()


class HealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class ModelBackendMetricsSnapshot:
    generated_at_utc: str
    uptime_seconds: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    policy_denials: int
    fallback_triggers_count: int
    total_prompt_tokens: int
    total_completion_tokens: int
    total_tokens: int
    average_latency_ms: float
    health_status: HealthStatus
    provider_breakdown: Dict[str, int] = field(default_factory=dict)

    def validate(self) -> None:
        """Validates MODOBS-INV1..MODOBS-INV5."""
        if not (self.generated_at_utc or "").strip():
            raise ValueError("generated_at_utc cannot be empty")
        try:
            datetime.fromisoformat(self.generated_at_utc.replace("Z", "+00:00"))
        except Exception as e:
            raise ValueError(f"generated_at_utc must be valid ISO timestamp: {e}")

        if self.total_requests != (self.successful_requests + self.failed_requests):
            raise ValueError(
                f"total_requests ({self.total_requests}) != successful ({self.successful_requests}) + failed ({self.failed_requests})"
            )

        if self.total_tokens != (self.total_prompt_tokens + self.total_completion_tokens):
            raise ValueError(
                f"total_tokens ({self.total_tokens}) != prompt ({self.total_prompt_tokens}) + completion ({self.total_completion_tokens})"
            )

        if self.uptime_seconds < 0.0:
            raise ValueError(f"uptime_seconds ({self.uptime_seconds}) cannot be negative")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at_utc": self.generated_at_utc,
            "uptime_seconds": round(self.uptime_seconds, 2),
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "policy_denials": self.policy_denials,
            "fallback_triggers_count": self.fallback_triggers_count,
            "total_prompt_tokens": self.total_prompt_tokens,
            "total_completion_tokens": self.total_completion_tokens,
            "total_tokens": self.total_tokens,
            "average_latency_ms": round(self.average_latency_ms, 3),
            "health_status": self.health_status.value,
            "provider_breakdown": dict(self.provider_breakdown),
        }


class ModelBackendObservabilityService:
    """Thread-safe service aggregating real-time metrics and generating point-in-time observability snapshots."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._start_time: float = time.monotonic()
        self._total_requests: int = 0
        self._successful_requests: int = 0
        self._failed_requests: int = 0
        self._policy_denials: int = 0
        self._fallback_triggers_count: int = 0
        self._total_prompt_tokens: int = 0
        self._total_completion_tokens: int = 0
        self._total_duration_ms: float = 0.0
        self._provider_counts: Dict[str, int] = {}

    def record_completion(
        self,
        provider: str,
        duration_ms: float,
        prompt_tokens: int,
        completion_tokens: int,
        fallback_used: bool = False,
    ) -> None:
        """Records a successful model completion."""
        safe_provider = sanitize_telemetry_text(provider) or "unknown"
        with self._lock:
            self._total_requests += 1
            self._successful_requests += 1
            self._total_prompt_tokens += max(0, prompt_tokens)
            self._total_completion_tokens += max(0, completion_tokens)
            self._total_duration_ms += max(0.0, duration_ms)
            self._provider_counts[safe_provider] = self._provider_counts.get(safe_provider, 0) + 1
            if fallback_used:
                self._fallback_triggers_count += 1

    def record_failure(self, provider: str, error_type: str) -> None:
        """Records a failed model dispatch."""
        safe_provider = sanitize_telemetry_text(provider) or "unknown"
        with self._lock:
            self._total_requests += 1
            self._failed_requests += 1
            self._provider_counts[safe_provider] = self._provider_counts.get(safe_provider, 0) + 1

    def record_policy_denial(self) -> None:
        """Records an authorization refusal under PoR Invariant I-2."""
        with self._lock:
            self._policy_denials += 1

    def get_snapshot(self) -> ModelBackendMetricsSnapshot:
        """Computes and returns an immutable metrics snapshot."""
        with self._lock:
            uptime = max(0.0, time.monotonic() - self._start_time)
            avg_latency = (
                round(self._total_duration_ms / self._successful_requests, 3)
                if self._successful_requests > 0
                else 0.0
            )

            # Health classification
            if self._total_requests == 0:
                health = HealthStatus.HEALTHY
            else:
                error_rate = self._failed_requests / self._total_requests
                if error_rate >= 0.25:
                    health = HealthStatus.CRITICAL
                elif error_rate >= 0.05 or self._fallback_triggers_count > 0:
                    health = HealthStatus.DEGRADED
                else:
                    health = HealthStatus.HEALTHY

            snapshot = ModelBackendMetricsSnapshot(
                generated_at_utc=datetime.now(timezone.utc).isoformat(),
                uptime_seconds=uptime,
                total_requests=self._total_requests,
                successful_requests=self._successful_requests,
                failed_requests=self._failed_requests,
                policy_denials=self._policy_denials,
                fallback_triggers_count=self._fallback_triggers_count,
                total_prompt_tokens=self._total_prompt_tokens,
                total_completion_tokens=self._total_completion_tokens,
                total_tokens=self._total_prompt_tokens + self._total_completion_tokens,
                average_latency_ms=avg_latency,
                health_status=health,
                provider_breakdown=dict(self._provider_counts),
            )

        snapshot.validate()
        return snapshot

    def reset(self) -> None:
        """Resets all metrics counters."""
        with self._lock:
            self._start_time = time.monotonic()
            self._total_requests = 0
            self._successful_requests = 0
            self._failed_requests = 0
            self._policy_denials = 0
            self._fallback_triggers_count = 0
            self._total_prompt_tokens = 0
            self._total_completion_tokens = 0
            self._total_duration_ms = 0.0
            self._provider_counts.clear()


_GLOBAL_OBSERVABILITY_SERVICE = ModelBackendObservabilityService()


def get_global_observability_service() -> ModelBackendObservabilityService:
    """Returns the process-wide ModelBackendObservabilityService singleton."""
    return _GLOBAL_OBSERVABILITY_SERVICE


def register_model_observability_tools(mcp_server: Any) -> None:
    """Registers Model Backend Adapters Observability MCP tools (T-03238)."""

    @mcp_server.tool()
    def aios_model_observability_snapshot() -> dict:
        """Returns the point-in-time metrics and health snapshot for model backend adapters (pure read-only, 0 tokens)."""
        snapshot = get_global_observability_service().get_snapshot()
        return {
            "status": "success",
            "ok": True,
            "data": snapshot.to_dict(),
        }
