"""Incident Response Runbooks Core Service (IR-SVC1..IR-SVC5).

Provides execution state machine, template interpolation, step dispatch,
and session management for Incident Response Runbooks.
"""

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Any

from .audit_client import utcnow_iso
from .incident_runbook_data_model import (
    RunbookSpec,
    RunbookStep,
    validate_action_template,
    RUNBOOK_ERR_INVALID_TEMPLATE,
)

RUNBOOK_ERR_SESSION_NOT_FOUND = "RUNBOOK_ERR_SESSION_NOT_FOUND"
RUNBOOK_ERR_INVALID_TRANSITION = "RUNBOOK_ERR_INVALID_TRANSITION"
RUNBOOK_ERR_MISSING_CONFIRMATION = "RUNBOOK_ERR_MISSING_CONFIRMATION"
RUNBOOK_ERR_MISSING_CAPABILITY = "RUNBOOK_ERR_MISSING_CAPABILITY"
RUNBOOK_ERR_TIMEOUT_EXCEEDED = "RUNBOOK_ERR_TIMEOUT_EXCEEDED"
RUNBOOK_ERR_PARAMETER_NOT_FOUND = "RUNBOOK_ERR_PARAMETER_NOT_FOUND"


class StepExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"

    @classmethod
    def parse_status(cls, s: str) -> "StepExecutionStatus":
        normalized = s.strip().lower()
        mapping = {
            "pending": cls.PENDING,
            "running": cls.RUNNING,
            "awaiting_confirmation": cls.AWAITING_CONFIRMATION,
            "confirm": cls.AWAITING_CONFIRMATION,
            "completed": cls.COMPLETED,
            "done": cls.COMPLETED,
            "failed": cls.FAILED,
            "timed_out": cls.TIMED_OUT,
            "timeout": cls.TIMED_OUT,
            "skipped": cls.SKIPPED,
        }
        if normalized in mapping:
            return mapping[normalized]
        raise ValueError(f"Unknown StepExecutionStatus '{s}'")


class RunbookExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"

    @classmethod
    def parse_status(cls, s: str) -> "RunbookExecutionStatus":
        normalized = s.strip().lower()
        mapping = {
            "pending": cls.PENDING,
            "running": cls.RUNNING,
            "awaiting_confirmation": cls.AWAITING_CONFIRMATION,
            "completed": cls.COMPLETED,
            "failed": cls.FAILED,
            "aborted": cls.ABORTED,
        }
        if normalized in mapping:
            return mapping[normalized]
        raise ValueError(f"Unknown RunbookExecutionStatus '{s}'")


def render_action_template(template: str, parameters: dict[str, str]) -> str:
    validate_action_template(template)

    def replacer(match: re.Match) -> str:
        param_name = match.group(1).strip()
        if param_name not in parameters:
            raise ValueError(f"{RUNBOOK_ERR_PARAMETER_NOT_FOUND}: Missing parameter '{param_name}'")
        val = parameters[param_name]
        if any(c in val for c in (";", "|", "&", "`", "$", "\n")):
            raise ValueError(f"{RUNBOOK_ERR_INVALID_TEMPLATE}: Parameter '{param_name}' contains forbidden shell characters")
        return val

    return re.sub(r"\{([^}]+)\}", replacer, template)


@dataclass
class StepExecutionRecord:
    step_id: str
    command_rendered: str
    status: StepExecutionStatus = StepExecutionStatus.PENDING
    started_at: str = ""
    completed_at: str = ""
    exit_code: int | None = None
    output: str = ""
    error_message: str | None = None


@dataclass
class RunbookExecutionSession:
    session_id: str
    runbook_id: str
    incident_id: str
    parameters: dict[str, str] = field(default_factory=dict)
    status: RunbookExecutionStatus = RunbookExecutionStatus.PENDING
    current_step_index: int = 0
    step_records: list[StepExecutionRecord] = field(default_factory=list)
    operator_confirmed: bool = False
    started_at: str = ""
    completed_at: str = ""

    def __post_init__(self):
        if not self.started_at:
            self.started_at = utcnow_iso()

    @classmethod
    def init_from_spec(
        cls,
        spec: RunbookSpec,
        incident_id: str,
        parameters: dict[str, str],
    ) -> "RunbookExecutionSession":
        spec.validate()
        step_records = []
        for step in spec.steps:
            rendered = render_action_template(step.action_template, parameters)
            step_records.append(
                StepExecutionRecord(
                    step_id=step.id,
                    command_rendered=rendered,
                )
            )

        now = utcnow_iso()
        session_id = f"SES-{spec.id}-{now.replace(':', '-')}"
        return cls(
            session_id=session_id,
            runbook_id=spec.id,
            incident_id=incident_id,
            parameters=parameters,
            status=RunbookExecutionStatus.PENDING,
            current_step_index=0,
            step_records=step_records,
            operator_confirmed=False,
            started_at=now,
        )

    def is_terminal(self) -> bool:
        return self.status in (
            RunbookExecutionStatus.COMPLETED,
            RunbookExecutionStatus.FAILED,
            RunbookExecutionStatus.ABORTED,
        )
