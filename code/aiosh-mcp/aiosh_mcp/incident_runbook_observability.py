"""Incident Response Runbooks Observability Subsystem (T-03033..T-03042).

Provides point-in-time metrics aggregation, execution state summaries,
phase progression, scan budgets, and policy compliance posture.
"""

from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any

from .incident_runbook_data_model import IncidentCategory, RunbookCatalogSnapshot, RunbookPhase
from .incident_runbook_policy import RunbookEnforcementMode, RunbookSecurityPolicy

MAX_OBSERVABILITY_PAYLOAD_BYTES: int = 64 * 1024
MAX_OBSERVABILITY_ENTRIES: int = 128
MAX_OBSERVABILITY_TEXT_LEN: int = 256
MAX_OBSERVABILITY_ACTIVE_SESSIONS: int = 100_000

IROBS_ERR_VALIDATION: str = "IROBS_ERR_VALIDATION"
IROBS_ERR_INACCESSIBLE: str = "IROBS_ERR_INACCESSIBLE"
IROBS_ERR_IO: str = "IROBS_ERR_IO"


@dataclass
class ObservabilityResultEnvelope:
    ok: bool
    snapshot: RunbookObservabilitySnapshot | None = None
    error_code: str | None = None
    error_message: str | None = None
    audit_row_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "snapshot": self.snapshot.to_dict() if self.snapshot else None,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "audit_row_required": self.audit_row_required,
        }

    @classmethod
    def success(cls, snapshot: RunbookObservabilitySnapshot) -> ObservabilityResultEnvelope:
        return cls(ok=True, snapshot=snapshot, audit_row_required=False)

    @classmethod
    def permissive_degraded(
        cls, snapshot: RunbookObservabilitySnapshot, reason: str
    ) -> ObservabilityResultEnvelope:
        return cls(ok=True, snapshot=snapshot, error_message=reason, audit_row_required=True)

    @classmethod
    def failure(cls, code: str, message: str) -> ObservabilityResultEnvelope:
        return cls(ok=False, error_code=code, error_message=message, audit_row_required=True)


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
    def generate_snapshot_safe(
        cls,
        catalog: RunbookCatalogSnapshot | None = None,
        active_sessions: dict[str, Any] | None = None,
        policy: RunbookSecurityPolicy | None = None,
    ) -> ObservabilityResultEnvelope:
        sessions = active_sessions or {}
        if len(sessions) > MAX_OBSERVABILITY_ACTIVE_SESSIONS:
            return ObservabilityResultEnvelope.failure(
                IROBS_ERR_VALIDATION,
                f"active_sessions count {len(sessions)} exceeds sanity limit {MAX_OBSERVABILITY_ACTIVE_SESSIONS}",
            )
        try:
            snapshot = cls.generate_snapshot(catalog=catalog, active_sessions=sessions, policy=policy)
            if not snapshot.is_healthy:
                return ObservabilityResultEnvelope.permissive_degraded(
                    snapshot,
                    "Active session count exceeds configured policy limit",
                )
            return ObservabilityResultEnvelope.success(snapshot)
        except Exception as e:
            return ObservabilityResultEnvelope.failure(IROBS_ERR_VALIDATION, str(e))

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

        if not (0.0 <= snapshot.active_sessions_utilization_percent <= 10000.0):
            raise ValueError(f"{IROBS_ERR_VALIDATION}: active_sessions_utilization_percent out of bounds [0, 10000]")

        serialized = json.dumps(snapshot.to_dict())
        if len(serialized.encode("utf-8")) > MAX_OBSERVABILITY_PAYLOAD_BYTES:
            raise ValueError(
                f"{IROBS_ERR_VALIDATION}: Snapshot payload exceeds maximum {MAX_OBSERVABILITY_PAYLOAD_BYTES} bytes"
            )

    @classmethod
    def save_snapshot_atomic(cls, path: str | Path, snapshot: RunbookObservabilitySnapshot) -> None:
        cls.validate_snapshot(snapshot)
        p = Path(path)
        data = snapshot.to_dict()
        serialized = json.dumps(data, indent=2)
        if len(serialized.encode("utf-8")) > MAX_OBSERVABILITY_PAYLOAD_BYTES:
            raise ValueError(
                f"{IROBS_ERR_IO}: Serialized snapshot size exceeds {MAX_OBSERVABILITY_PAYLOAD_BYTES} bytes"
            )

        temp_path = p.with_name(f"{p.name}.tmp.{os.getpid()}")
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(serialized)
            os.replace(temp_path, p)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise

    @classmethod
    def load_snapshot_file(cls, path: str | Path) -> RunbookObservabilitySnapshot:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"{IROBS_ERR_INACCESSIBLE}: Snapshot file not found: {path}")

        if p.stat().st_size > MAX_OBSERVABILITY_PAYLOAD_BYTES:
            raise ValueError(
                f"{IROBS_ERR_VALIDATION}: Snapshot file size exceeds {MAX_OBSERVABILITY_PAYLOAD_BYTES} bytes"
            )

        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

        mode_val = data.get("policy_mode", RunbookEnforcementMode.ENFORCING.value)
        snapshot = RunbookObservabilitySnapshot(
            generated_at_utc=data.get("generated_at_utc", ""),
            total_catalog_runbooks=data.get("total_catalog_runbooks", 0),
            total_executions=data.get("total_executions", 0),
            executions_by_category=data.get("executions_by_category", {}),
            executions_by_status=data.get("executions_by_status", {}),
            step_executions_by_phase=data.get("step_executions_by_phase", {}),
            total_ports_scanned=data.get("total_ports_scanned", 0),
            total_files_scanned=data.get("total_files_scanned", 0),
            total_web_paths_scanned=data.get("total_web_paths_scanned", 0),
            policy_mode=RunbookEnforcementMode(mode_val),
            high_risk_confirmations_total=data.get("high_risk_confirmations_total", 0),
            policy_rejections_total=data.get("policy_rejections_total", 0),
            active_sessions_count=data.get("active_sessions_count", 0),
            active_sessions_utilization_percent=float(data.get("active_sessions_utilization_percent", 0.0)),
            is_healthy=data.get("is_healthy", True),
            recent_audit_events_count=data.get("recent_audit_events_count", 0),
        )
        cls.validate_snapshot(snapshot)
        return snapshot
