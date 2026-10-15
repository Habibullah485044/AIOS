"""Incident Response Runbooks Security Policy Subsystem (T-03023..T-03032).

Provides policy-driven governance over runbook start, confirmation gating,
substrate access, and security scanning budgets.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum

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

    def evaluate_runbook_start(self, spec: RunbookSpec) -> None:
        raise NotImplementedError("evaluate_runbook_start scaffold - pending T-03026")

    def evaluate_step_advance(self, step: RunbookStep, operator_confirmed: bool) -> None:
        raise NotImplementedError("evaluate_step_advance scaffold - pending T-03026")

    def evaluate_scan_operation(self, action: str, ports_count: int, depth: int) -> None:
        raise NotImplementedError("evaluate_scan_operation scaffold - pending T-03026")

    @classmethod
    def load_from_file(cls, path: str) -> "RunbookSecurityPolicy":
        raise NotImplementedError("load_from_file scaffold - pending T-03026")

    def save_to_file(self, path: str) -> None:
        raise NotImplementedError("save_to_file scaffold - pending T-03026")
