"""Incident Response Runbooks Observability Subsystem (T-03033..T-03042).

Provides point-in-time metrics aggregation, execution state summaries,
phase progression, scan budgets, and policy compliance posture.
"""

from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
from typing import Any

from .incident_runbook_data_model import IncidentCategory, RunbookCatalogSnapshot, RunbookPhase
from .incident_runbook_policy import RunbookEnforcementMode, RunbookSecurityPolicy

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

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["policy_mode"] = self.policy_mode.value
        return d


class RunbookObservabilityService:
    @classmethod
    def generate_snapshot(
        cls,
        catalog: RunbookCatalogSnapshot | None = None,
        active_sessions: dict[str, Any] | None = None,
        policy: RunbookSecurityPolicy | None = None,
    ) -> RunbookObservabilitySnapshot:
        cat = catalog or RunbookCatalogSnapshot.canonical_baseline()
        pol = policy or RunbookSecurityPolicy()
        sessions = active_sessions or {}

        executions_by_category: dict[str, int] = {}
        step_executions_by_phase: dict[str, int] = {}

        for rb in cat.runbooks:
            cat_key = rb.category.value
            executions_by_category[cat_key] = executions_by_category.get(cat_key, 0) + 1
            for step in rb.steps:
                phase_key = step.phase.value
                step_executions_by_phase[phase_key] = step_executions_by_phase.get(phase_key, 0) + 1

        active_count = len(sessions)
        executions_by_status = {
            "active": active_count,
            "completed": 0,
            "failed": 0,
            "aborted": 0,
        }

        max_sessions = float(pol.max_active_sessions) if pol.max_active_sessions > 0 else 100.0
        utilization = round((active_count / max_sessions) * 100.0, 1)
        is_healthy = active_count <= pol.max_active_sessions

        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        snapshot = RunbookObservabilitySnapshot(
            generated_at_utc=now_utc,
            total_catalog_runbooks=len(cat.runbooks),
            total_executions=len(cat.runbooks) + active_count,
            executions_by_category=executions_by_category,
            executions_by_status=executions_by_status,
            step_executions_by_phase=step_executions_by_phase,
            total_ports_scanned=0,
            total_files_scanned=0,
            total_web_paths_scanned=0,
            policy_mode=pol.mode,
            high_risk_confirmations_total=0,
            policy_rejections_total=0,
            active_sessions_count=active_count,
            active_sessions_utilization_percent=utilization,
            is_healthy=is_healthy,
            recent_audit_events_count=0,
        )

        cls.validate_snapshot(snapshot)
        return snapshot

    @classmethod
    def validate_snapshot(cls, snapshot: RunbookObservabilitySnapshot) -> None:
        if not snapshot.generated_at_utc or len(snapshot.generated_at_utc) > MAX_OBSERVABILITY_TEXT_LEN:
            raise ValueError(f"{IROBS_ERR_VALIDATION}: generated_at_utc length invalid")

        if len(snapshot.executions_by_category) > MAX_OBSERVABILITY_ENTRIES:
            raise ValueError(f"{IROBS_ERR_VALIDATION}: executions_by_category exceeds max entries")

        if len(snapshot.executions_by_status) > MAX_OBSERVABILITY_ENTRIES:
            raise ValueError(f"{IROBS_ERR_VALIDATION}: executions_by_status exceeds max entries")

        if len(snapshot.step_executions_by_phase) > MAX_OBSERVABILITY_ENTRIES:
            raise ValueError(f"{IROBS_ERR_VALIDATION}: step_executions_by_phase exceeds max entries")

        if not (0.0 <= snapshot.active_sessions_utilization_percent <= 100.0):
            raise ValueError(f"{IROBS_ERR_VALIDATION}: active_sessions_utilization_percent out of bounds [0, 100]")

        serialized = json.dumps(snapshot.to_dict())
        if len(serialized.encode("utf-8")) > MAX_OBSERVABILITY_PAYLOAD_BYTES:
            raise ValueError(
                f"{IROBS_ERR_VALIDATION}: Snapshot payload exceeds maximum {MAX_OBSERVABILITY_PAYLOAD_BYTES} bytes"
            )
