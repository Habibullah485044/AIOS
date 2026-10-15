"""Incident Response Runbooks Security Policy Subsystem (T-03023..T-03032).

Provides policy-driven governance over runbook start, confirmation gating,
substrate access, and security scanning budgets.
"""

from __future__ import annotations
import json
import os
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path

from .incident_runbook_data_model import (
    IncidentCategory,
    RunbookSpec,
    RunbookStep,
    RunbookTargetSubstrate,
)

MAX_RUNBOOK_POLICY_BYTES: int = 64 * 1024
DEFAULT_MAX_STEP_TIMEOUT_SECS: int = 60
MAX_PERMISSIBLE_STEP_TIMEOUT_SECS: int = 300
DEFAULT_MAX_SCANNED_PORTS: int = 10_000
DEFAULT_MAX_FILE_SCAN_DEPTH: int = 16
DEFAULT_MAX_FILE_SCAN_BYTES: int = 16 * 1024 * 1024

RUNBOOKPOL_ERR_VALIDATION: str = "RUNBOOKPOL_ERR_VALIDATION"
RUNBOOKPOL_ERR_POLICY_VIOLATION: str = "RUNBOOKPOL_ERR_POLICY_VIOLATION"
RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED: str = "RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED"
RUNBOOKPOL_ERR_CATEGORY_DISALLOWED: str = "RUNBOOKPOL_ERR_CATEGORY_DISALLOWED"
RUNBOOKPOL_ERR_SUBSTRATE_DISALLOWED: str = "RUNBOOKPOL_ERR_SUBSTRATE_DISALLOWED"
RUNBOOKPOL_ERR_SCAN_BOUNDS: str = "RUNBOOKPOL_ERR_SCAN_BOUNDS"
RUNBOOKPOL_ERR_IO: str = "RUNBOOKPOL_ERR_IO"


class RunbookEnforcementMode(str, Enum):
    ENFORCING = "enforcing"
    PERMISSIVE = "permissive"
    DISABLED = "disabled"


@dataclass
class PolicyResultEnvelope:
    ok: bool
    error_code: str | None = None
    error_message: str | None = None
    audit_row_required: bool = False

    @classmethod
    def success(cls) -> "PolicyResultEnvelope":
        return cls(ok=True)

    @classmethod
    def success_audited(cls) -> "PolicyResultEnvelope":
        return cls(ok=True, audit_row_required=True)

    @classmethod
    def failure(cls, code: str, msg: str) -> "PolicyResultEnvelope":
        return cls(ok=False, error_code=code, error_message=msg, audit_row_required=True)


@dataclass
class RunbookSecurityPolicy:
    version: str = "1.0.0"
    mode: RunbookEnforcementMode = RunbookEnforcementMode.ENFORCING
    require_operator_confirmation_for_high_risk: bool = True
    max_step_timeout_seconds: int = DEFAULT_MAX_STEP_TIMEOUT_SECS
    max_active_sessions: int = 100
    disallowed_categories: list[IncidentCategory] = field(default_factory=list)
    disallowed_substrates: list[RunbookTargetSubstrate] = field(default_factory=list)
    max_scanned_ports: int = DEFAULT_MAX_SCANNED_PORTS
    max_file_scan_depth: int = DEFAULT_MAX_FILE_SCAN_DEPTH
    max_file_scan_size_bytes: int = DEFAULT_MAX_FILE_SCAN_BYTES
    require_pep_grant: bool = True

    def validate_bounds(self) -> None:
        if self.max_step_timeout_seconds <= 0 or self.max_step_timeout_seconds > MAX_PERMISSIBLE_STEP_TIMEOUT_SECS:
            raise ValueError(
                f"{RUNBOOKPOL_ERR_VALIDATION}: max_step_timeout_seconds {self.max_step_timeout_seconds} out of bounds [1, {MAX_PERMISSIBLE_STEP_TIMEOUT_SECS}]"
            )
        if self.max_scanned_ports <= 0 or self.max_scanned_ports > 65_535:
            raise ValueError(
                f"{RUNBOOKPOL_ERR_VALIDATION}: max_scanned_ports {self.max_scanned_ports} out of bounds [1, 65535]"
            )
        if self.max_file_scan_depth <= 0 or self.max_file_scan_depth > 32:
            raise ValueError(
                f"{RUNBOOKPOL_ERR_VALIDATION}: max_file_scan_depth {self.max_file_scan_depth} out of bounds [1, 32]"
            )

    def evaluate_runbook_start(self, spec: RunbookSpec) -> None:
        if self.mode == RunbookEnforcementMode.DISABLED:
            return

        if spec.category in self.disallowed_categories:
            raise ValueError(
                f"{RUNBOOKPOL_ERR_CATEGORY_DISALLOWED}: Category '{spec.category}' is disallowed by security policy"
            )

        for step in spec.steps:
            if step.target in self.disallowed_substrates:
                raise ValueError(
                    f"{RUNBOOKPOL_ERR_SUBSTRATE_DISALLOWED}: Target substrate '{step.target}' in step '{step.id}' is disallowed by security policy"
                )

    def evaluate_step_advance(self, step: RunbookStep, operator_confirmed: bool) -> None:
        if self.mode == RunbookEnforcementMode.DISABLED:
            return

        if (
            self.require_operator_confirmation_for_high_risk
            and step.is_high_risk()
            and not operator_confirmed
        ):
            raise ValueError(
                f"{RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED}: Step '{step.id}' requires explicit operator confirmation under policy"
            )

        if step.timeout_seconds > self.max_step_timeout_seconds:
            raise ValueError(
                f"{RUNBOOKPOL_ERR_POLICY_VIOLATION}: Step '{step.id}' timeout {step.timeout_seconds}s exceeds policy maximum {self.max_step_timeout_seconds}s"
            )

    def evaluate_step_with_envelope(
        self, step: RunbookStep, operator_confirmed: bool
    ) -> PolicyResultEnvelope:
        if self.mode == RunbookEnforcementMode.DISABLED:
            return PolicyResultEnvelope.success_audited()

        if (
            self.require_operator_confirmation_for_high_risk
            and step.is_high_risk()
            and not operator_confirmed
        ):
            if self.mode == RunbookEnforcementMode.PERMISSIVE:
                return PolicyResultEnvelope.success_audited()
            return PolicyResultEnvelope.failure(
                RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED,
                f"Step '{step.id}' requires explicit operator confirmation under policy",
            )

        if step.timeout_seconds > self.max_step_timeout_seconds:
            if self.mode == RunbookEnforcementMode.PERMISSIVE:
                return PolicyResultEnvelope.success_audited()
            return PolicyResultEnvelope.failure(
                RUNBOOKPOL_ERR_POLICY_VIOLATION,
                f"Step '{step.id}' timeout {step.timeout_seconds}s exceeds policy maximum {self.max_step_timeout_seconds}s",
            )

        return PolicyResultEnvelope.success()

    def evaluate_scan_operation(self, action: str, ports_count: int, depth: int) -> None:
        if self.mode == RunbookEnforcementMode.DISABLED:
            return

        if ports_count > self.max_scanned_ports:
            raise ValueError(
                f"{RUNBOOKPOL_ERR_SCAN_BOUNDS}: Scanned ports count {ports_count} exceeds policy limit {self.max_scanned_ports}"
            )

        if depth > self.max_file_scan_depth:
            raise ValueError(
                f"{RUNBOOKPOL_ERR_SCAN_BOUNDS}: File scan depth {depth} exceeds policy limit {self.max_file_scan_depth}"
            )

    @classmethod
    def load_from_file(cls, path: str) -> "RunbookSecurityPolicy":
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"{RUNBOOKPOL_ERR_IO}: Policy file '{path}' does not exist")

        size = p.stat().st_size
        if size > MAX_RUNBOOK_POLICY_BYTES:
            raise ValueError(
                f"{RUNBOOKPOL_ERR_IO}: Policy file size {size} bytes exceeds maximum {MAX_RUNBOOK_POLICY_BYTES}"
            )

        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

        mode_str = data.get("mode", "enforcing")
        mode = RunbookEnforcementMode(mode_str)

        cats = [IncidentCategory(c) for c in data.get("disallowed_categories", [])]
        subs = [RunbookTargetSubstrate(s) for s in data.get("disallowed_substrates", [])]

        policy = cls(
            version=data.get("version", "1.0.0"),
            mode=mode,
            require_operator_confirmation_for_high_risk=data.get(
                "require_operator_confirmation_for_high_risk", True
            ),
            max_step_timeout_seconds=data.get(
                "max_step_timeout_seconds", DEFAULT_MAX_STEP_TIMEOUT_SECS
            ),
            max_active_sessions=data.get("max_active_sessions", 100),
            disallowed_categories=cats,
            disallowed_substrates=subs,
            max_scanned_ports=data.get("max_scanned_ports", DEFAULT_MAX_SCANNED_PORTS),
            max_file_scan_depth=data.get("max_file_scan_depth", DEFAULT_MAX_FILE_SCAN_DEPTH),
            max_file_scan_size_bytes=data.get(
                "max_file_scan_size_bytes", DEFAULT_MAX_FILE_SCAN_BYTES
            ),
            require_pep_grant=data.get("require_pep_grant", True),
        )
        policy.validate_bounds()
        return policy

    def save_to_file(self, path: str) -> None:
        self.validate_bounds()
        p = Path(path)
        data = asdict(self)
        data["mode"] = self.mode.value
        data["disallowed_categories"] = [c.value for c in self.disallowed_categories]
        data["disallowed_substrates"] = [s.value for s in self.disallowed_substrates]

        serialized = json.dumps(data, indent=2)
        if len(serialized.encode("utf-8")) > MAX_RUNBOOK_POLICY_BYTES:
            raise ValueError(
                f"{RUNBOOKPOL_ERR_IO}: Serialized policy size exceeds {MAX_RUNBOOK_POLICY_BYTES} bytes"
            )

        temp_path = p.with_suffix(f".tmp.{os.getpid()}")
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(serialized)
            os.replace(temp_path, p)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise
