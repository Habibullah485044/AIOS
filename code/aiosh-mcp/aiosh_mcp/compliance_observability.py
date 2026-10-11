"""Compliance Mapping Observability Subsystem (COMPOBS1..COMPOBS6).

Provides point-in-time metrics aggregation, regulatory framework distributions,
lifecycle status distributions, target component distributions, posture scoring,
capacity utilization telemetry, and audit trail correlation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
from typing import Any

COMPOBS_ERR_VALIDATION = "COMPOBS_ERR_VALIDATION"
COMPOBS_ERR_SERVICE_INACCESSIBLE = "COMPOBS_ERR_SERVICE_INACCESSIBLE"

MAX_TELEMETRY_TEXT_LEN = 256
MAX_OUTCOME_DISTRIBUTION_ENTRIES = 128
MAX_AUDIT_LOG_TAIL_ITEMS = 1000
MAX_COMPLIANCE_ENTRIES_CAPACITY = 1024


def sanitize_telemetry_text(s: str) -> str:
    """Sanitizes telemetry text by filtering control characters and enforcing bounds."""
    filtered = "".join(c for c in s if not ord(c) < 32 and ord(c) != 127)
    return filtered[:MAX_TELEMETRY_TEXT_LEN].strip()


@dataclass
class ComplianceObservabilityReport:
    generated_at_utc: str = ""
    total_mappings: int = 0
    mappings_by_framework: dict[str, int] = field(default_factory=dict)
    mappings_by_status: dict[str, int] = field(default_factory=dict)
    mappings_by_target_type: dict[str, int] = field(default_factory=dict)
    compliance_percentage: float = 0.0
    gap_control_count: int = 0
    policy_mode: str = "unconfigured"
    capacity_utilization_percent: int = 0
    is_healthy: bool = True
    recent_audit_events_count: int = 0

    def validate(self) -> None:
        """Validates report invariants."""
        if not (self.generated_at_utc or "").strip():
            raise ValueError(f"{COMPOBS_ERR_VALIDATION}: generated_at_utc cannot be empty")
        try:
            datetime.fromisoformat(self.generated_at_utc.replace("Z", "+00:00"))
        except Exception as e:
            raise ValueError(f"{COMPOBS_ERR_VALIDATION}: generated_at_utc must be valid ISO/RFC3339 timestamp: {e}")

        if len(self.mappings_by_framework) > MAX_OUTCOME_DISTRIBUTION_ENTRIES:
            raise ValueError(f"{COMPOBS_ERR_VALIDATION}: mappings_by_framework exceeds maximum entries")
        if len(self.mappings_by_status) > MAX_OUTCOME_DISTRIBUTION_ENTRIES:
            raise ValueError(f"{COMPOBS_ERR_VALIDATION}: mappings_by_status exceeds maximum entries")
        if len(self.mappings_by_target_type) > MAX_OUTCOME_DISTRIBUTION_ENTRIES:
            raise ValueError(f"{COMPOBS_ERR_VALIDATION}: mappings_by_target_type exceeds maximum entries")

        if not (0.0 <= self.compliance_percentage <= 100.0) or math.isnan(self.compliance_percentage):
            raise ValueError(f"{COMPOBS_ERR_VALIDATION}: compliance_percentage must be between 0.0 and 100.0")

        if not (0 <= self.capacity_utilization_percent <= 100):
            raise ValueError(f"{COMPOBS_ERR_VALIDATION}: capacity_utilization_percent cannot exceed 100")

        all_keys = list(self.mappings_by_framework.keys()) + list(self.mappings_by_status.keys()) + list(self.mappings_by_target_type.keys())
        for k in all_keys:
            if len(k) > MAX_TELEMETRY_TEXT_LEN:
                raise ValueError(f"{COMPOBS_ERR_VALIDATION}: distribution key exceeds max length")
            if any(ord(c) < 32 or ord(c) == 127 for c in k):
                raise ValueError(f"{COMPOBS_ERR_VALIDATION}: distribution key contains control characters")


def generate_compliance_observability_report(
    snapshot: Any,
    policy: Any = None,
    ring: Any = None,
) -> ComplianceObservabilityReport:
    """Generates a point-in-time observability report."""
    mappings = snapshot.mappings if hasattr(snapshot, "mappings") else []
    total = len(mappings)

    mappings_by_framework: dict[str, int] = {}
    mappings_by_status: dict[str, int] = {}
    mappings_by_target_type: dict[str, int] = {}

    for entry in mappings:
        fw_val = getattr(entry, "framework", "")
        fw_str = sanitize_telemetry_text(fw_val.value if hasattr(fw_val, "value") else str(fw_val))
        if len(mappings_by_framework) < MAX_OUTCOME_DISTRIBUTION_ENTRIES or fw_str in mappings_by_framework:
            mappings_by_framework[fw_str] = mappings_by_framework.get(fw_str, 0) + 1

        stat_val = getattr(entry, "status", "")
        stat_str = sanitize_telemetry_text(stat_val.value if hasattr(stat_val, "value") else str(stat_val))
        if len(mappings_by_status) < MAX_OUTCOME_DISTRIBUTION_ENTRIES or stat_str in mappings_by_status:
            mappings_by_status[stat_str] = mappings_by_status.get(stat_str, 0) + 1

        tt_val = getattr(entry, "target_type", "")
        tt_str = sanitize_telemetry_text(tt_val.value if hasattr(tt_val, "value") else str(tt_val))
        if len(mappings_by_target_type) < MAX_OUTCOME_DISTRIBUTION_ENTRIES or tt_str in mappings_by_target_type:
            mappings_by_target_type[tt_str] = mappings_by_target_type.get(tt_str, 0) + 1

    compliant_count = sum(1 for m in mappings if (getattr(m, "status", "").value if hasattr(getattr(m, "status", ""), "value") else str(getattr(m, "status", ""))) == "compliant")
    compliance_percentage = 100.0 if total == 0 else (compliant_count / total) * 100.0
    gap_control_count = sum(1 for m in mappings if (getattr(m, "status", "").value if hasattr(getattr(m, "status", ""), "value") else str(getattr(m, "status", ""))) in ("partially_compliant", "non_compliant"))

    recent_audit_events_count = 0
    if ring is not None and hasattr(ring, "tail"):
        try:
            rows = ring.tail(MAX_AUDIT_LOG_TAIL_ITEMS)
            for row in rows:
                tool = getattr(row, "tool", "") or (row.get("tool") if isinstance(row, dict) else "")
                if tool == "compliance" or tool.startswith("aios.compliance"):
                    recent_audit_events_count += 1
        except Exception:
            pass

    policy_mode = "unconfigured"
    if policy is not None and hasattr(policy, "mode"):
        m = policy.mode
        policy_mode = m.value if hasattr(m, "value") else str(m).lower()

    capacity_utilization_percent = min(100, int((min(total, MAX_COMPLIANCE_ENTRIES_CAPACITY) * 100) / MAX_COMPLIANCE_ENTRIES_CAPACITY))
    is_healthy = total <= MAX_COMPLIANCE_ENTRIES_CAPACITY and not math.isnan(compliance_percentage)

    now_iso = datetime.now(timezone.utc).isoformat()
    report = ComplianceObservabilityReport(
        generated_at_utc=now_iso,
        total_mappings=total,
        mappings_by_framework=mappings_by_framework,
        mappings_by_status=mappings_by_status,
        mappings_by_target_type=mappings_by_target_type,
        compliance_percentage=compliance_percentage,
        gap_control_count=gap_control_count,
        policy_mode=policy_mode,
        capacity_utilization_percent=capacity_utilization_percent,
        is_healthy=is_healthy,
        recent_audit_events_count=recent_audit_events_count,
    )
    report.validate()
    return report
