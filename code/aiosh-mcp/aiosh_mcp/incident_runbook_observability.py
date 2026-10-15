"""Incident Response Runbooks Observability Subsystem (T-03033..T-03042).

Provides point-in-time metrics aggregation, execution state summaries,
phase progression, scan budgets, and policy compliance posture.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from .incident_runbook_data_model import IncidentCategory, RunbookPhase
from .incident_runbook_policy import RunbookEnforcementMode

MAX_OBSERVABILITY_PAYLOAD_BYTES: int = 64 * 1024
MAX_OBSERVABILITY_ENTRIES: int = 128
MAX_OBSERVABILITY_TEXT_LEN: int = 256

IROBS_ERR_VALIDATION: str = "IROBS_ERR_VALIDATION"
IROBS_ERR_INACCESSIBLE: str = "IROBS_ERR_INACCESSIBLE"


@dataclass
class RunbookObservabilitySnapshot:
    generated_at_utc: str
    total_catalog_runbooks: int
    total_executions: int
    executions_by_category: dict[str, int] = field(default_factory=dict)
    executions_by_status: dict[str, int] = field(default_factory=dict)
    step_executions_by_phase: dict[str, int] = field(default_factory=dict)
    total_ports_scanned: int = 0
    total_files_scanned: int = 0
    total_web_paths_scanned: int = 0
    policy_mode: RunbookEnforcementMode = RunbookEnforcementMode.ENFORCING
    high_risk_confirmations_total: int = 0
    policy_rejections_total: int = 0
    active_sessions_count: int = 0
    active_sessions_utilization_percent: float = 0.0
    is_healthy: bool = True
    recent_audit_events_count: int = 0


class RunbookObservabilityService:
    @classmethod
    def generate_snapshot(cls) -> RunbookObservabilitySnapshot:
        # Scaffold stub: fails loudly until implementation in T-03036
        raise NotImplementedError("pending T-03036: RunbookObservabilityService.generate_snapshot")

    @classmethod
    def validate_snapshot(cls, snapshot: RunbookObservabilitySnapshot) -> None:
        # Scaffold stub: fails loudly until implementation in T-03036
        raise NotImplementedError("pending T-03036: RunbookObservabilityService.validate_snapshot")
