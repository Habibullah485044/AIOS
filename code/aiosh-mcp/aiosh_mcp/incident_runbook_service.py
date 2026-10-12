"""Incident Response Runbooks Core Service (IR-SVC1..IR-SVC5).

Provides execution state machine, template interpolation, step dispatch,
and session management for Incident Response Runbooks.
"""

from dataclasses import dataclass, field
from enum import Enum
import json
import re
from typing import Any

from .audit_client import utcnow_iso
from .incident_runbook_data_model import (
    RunbookSpec,
    RunbookStep,
    RunbookCatalogSnapshot,
    IncidentCategory,
    IncidentSeverity,
    validate_action_template,
    validate_identifier,
    RUNBOOK_ERR_INVALID_TEMPLATE,
    RUNBOOK_ERR_BOUNDS_EXCEEDED,
)

RUNBOOK_ERR_SESSION_NOT_FOUND = "RUNBOOK_ERR_SESSION_NOT_FOUND"
RUNBOOK_ERR_INVALID_TRANSITION = "RUNBOOK_ERR_INVALID_TRANSITION"
RUNBOOK_ERR_MISSING_CONFIRMATION = "RUNBOOK_ERR_MISSING_CONFIRMATION"
RUNBOOK_ERR_MISSING_CAPABILITY = "RUNBOOK_ERR_MISSING_CAPABILITY"
RUNBOOK_ERR_TIMEOUT_EXCEEDED = "RUNBOOK_ERR_TIMEOUT_EXCEEDED"
RUNBOOK_ERR_PARAMETER_NOT_FOUND = "RUNBOOK_ERR_PARAMETER_NOT_FOUND"
RUNBOOK_ERR_INVALID_PARAM_VALUE = "RUNBOOK_ERR_INVALID_PARAM_VALUE"

MAX_RUNBOOK_PARAM_LEN = 256
MAX_RUNBOOK_PARAMS_COUNT = 32


def validate_parameter_value(key: str, val: str) -> str:
    if not val:
        raise ValueError(f"{RUNBOOK_ERR_INVALID_PARAM_VALUE}: Parameter '{key}' value cannot be empty")
    if len(val) > MAX_RUNBOOK_PARAM_LEN:
        raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: Parameter '{key}' length {len(val)} exceeds max {MAX_RUNBOOK_PARAM_LEN}")
    if ".." in val:
        raise ValueError(f"{RUNBOOK_ERR_INVALID_PARAM_VALUE}: Parameter '{key}' contains illegal path traversal '..'")
    if not re.match(r"^[a-zA-Z0-9_\-\.:/]+$", val):
        raise ValueError(f"{RUNBOOK_ERR_INVALID_PARAM_VALUE}: Parameter '{key}' contains forbidden characters")
    return val



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
        validate_parameter_value(param_name, val)
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
        if len(parameters) > MAX_RUNBOOK_PARAMS_COUNT:
            raise ValueError(f"{RUNBOOK_ERR_BOUNDS_EXCEEDED}: Parameters count {len(parameters)} exceeds max {MAX_RUNBOOK_PARAMS_COUNT}")
        for k, v in parameters.items():
            validate_identifier(k, "Parameter key")
            validate_parameter_value(k, v)

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

    def advance_step(self, spec: RunbookSpec, simulate_success: bool = True) -> StepExecutionStatus:
        if self.is_terminal():
            raise ValueError(f"{RUNBOOK_ERR_INVALID_TRANSITION}: Cannot advance session in terminal state {self.status}")

        if self.current_step_index >= len(self.step_records):
            self.status = RunbookExecutionStatus.COMPLETED
            self.completed_at = utcnow_iso()
            return StepExecutionStatus.COMPLETED

        if self.current_step_index >= len(spec.steps):
            raise ValueError(f"{RUNBOOK_ERR_INVALID_TRANSITION}: Step index {self.current_step_index} out of bounds")

        step_def = spec.steps[self.current_step_index]

        # If step requires confirmation and operator hasn't confirmed yet:
        if (step_def.requires_confirmation or step_def.is_high_risk()) and not self.operator_confirmed:
            self.status = RunbookExecutionStatus.AWAITING_CONFIRMATION
            self.step_records[self.current_step_index].status = StepExecutionStatus.AWAITING_CONFIRMATION
            return StepExecutionStatus.AWAITING_CONFIRMATION

        # Execute step
        self.status = RunbookExecutionStatus.RUNNING
        record = self.step_records[self.current_step_index]
        record.status = StepExecutionStatus.RUNNING
        record.started_at = utcnow_iso()

        if simulate_success:
            record.status = StepExecutionStatus.COMPLETED
            record.completed_at = utcnow_iso()
            record.exit_code = 0
            record.output = f"Executed successfully: {record.command_rendered}"

            self.current_step_index += 1
            self.operator_confirmed = False

            if self.current_step_index >= len(self.step_records):
                self.status = RunbookExecutionStatus.COMPLETED
                self.completed_at = utcnow_iso()

            return StepExecutionStatus.COMPLETED
        else:
            record.status = StepExecutionStatus.FAILED
            record.completed_at = utcnow_iso()
            record.exit_code = 1
            record.error_message = "Execution simulated failure"

            self.status = RunbookExecutionStatus.FAILED
            self.completed_at = utcnow_iso()

            return StepExecutionStatus.FAILED

    def confirm_current_step(self, operator_id: str = "operator-default", token: str = "token-auto-approved") -> None:
        if self.status != RunbookExecutionStatus.AWAITING_CONFIRMATION:
            raise ValueError(f"{RUNBOOK_ERR_INVALID_TRANSITION}: Session is not awaiting confirmation")
        op_trimmed = operator_id.strip()
        if not op_trimmed or len(op_trimmed) > 64:
            raise ValueError(f"{RUNBOOK_ERR_MISSING_CONFIRMATION}: Invalid operator_id")
        tok_trimmed = token.strip()
        if not tok_trimmed or len(tok_trimmed) > 64:
            raise ValueError(f"{RUNBOOK_ERR_MISSING_CONFIRMATION}: Invalid confirmation token")
        self.operator_confirmed = True
        self.status = RunbookExecutionStatus.RUNNING

    def abort(self, reason: str = "") -> None:
        if self.is_terminal():
            raise ValueError(f"{RUNBOOK_ERR_INVALID_TRANSITION}: Session already in terminal state")
        self.status = RunbookExecutionStatus.ABORTED
        self.completed_at = utcnow_iso()
        if self.current_step_index < len(self.step_records):
            record = self.step_records[self.current_step_index]
            record.status = StepExecutionStatus.SKIPPED
            record.completed_at = utcnow_iso()
            record.error_message = f"Aborted: {reason}"

    def fail_current(self, error_message: str) -> None:
        if self.is_terminal():
            raise ValueError(f"{RUNBOOK_ERR_INVALID_TRANSITION}: Session already in terminal state")
        if self.current_step_index < len(self.step_records):
            record = self.step_records[self.current_step_index]
            record.status = StepExecutionStatus.FAILED
            record.completed_at = utcnow_iso()
            record.exit_code = 1
            record.error_message = error_message
        self.status = RunbookExecutionStatus.FAILED
        self.completed_at = utcnow_iso()

    def timeout_current(self) -> None:
        if self.is_terminal():
            raise ValueError(f"{RUNBOOK_ERR_INVALID_TRANSITION}: Session already in terminal state")
        if self.current_step_index < len(self.step_records):
            record = self.step_records[self.current_step_index]
            record.status = StepExecutionStatus.TIMED_OUT
            record.completed_at = utcnow_iso()
            record.exit_code = 124
            record.error_message = f"{RUNBOOK_ERR_TIMEOUT_EXCEEDED}: Step timeout exceeded"
        self.status = RunbookExecutionStatus.FAILED
        self.completed_at = utcnow_iso()

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "runbook_id": self.runbook_id,
            "incident_id": self.incident_id,
            "parameters": self.parameters,
            "status": self.status.value if isinstance(self.status, RunbookExecutionStatus) else str(self.status),
            "current_step_index": self.current_step_index,
            "step_records": [
                {
                    "step_id": r.step_id,
                    "command_rendered": r.command_rendered,
                    "status": r.status.value if isinstance(r.status, StepExecutionStatus) else str(r.status),
                    "started_at": r.started_at,
                    "completed_at": r.completed_at,
                    "exit_code": r.exit_code,
                    "output": r.output,
                    "error_message": r.error_message,
                }
                for r in self.step_records
            ],
            "operator_confirmed": self.operator_confirmed,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }

    def to_json(self, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RunbookExecutionSession":
        step_records = [
            StepExecutionRecord(
                step_id=r["step_id"],
                command_rendered=r["command_rendered"],
                status=StepExecutionStatus.parse_status(r["status"]),
                started_at=r.get("started_at", ""),
                completed_at=r.get("completed_at", ""),
                exit_code=r.get("exit_code"),
                output=r.get("output", ""),
                error_message=r.get("error_message"),
            )
            for r in data.get("step_records", [])
        ]
        return cls(
            session_id=data["session_id"],
            runbook_id=data["runbook_id"],
            incident_id=data["incident_id"],
            parameters=data.get("parameters", {}),
            status=RunbookExecutionStatus.parse_status(data["status"]),
            current_step_index=data.get("current_step_index", 0),
            step_records=step_records,
            operator_confirmed=data.get("operator_confirmed", False),
            started_at=data.get("started_at", ""),
            completed_at=data.get("completed_at", ""),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "RunbookExecutionSession":
        return cls.from_dict(json.loads(json_str))


def match_runbook(
    catalog: RunbookCatalogSnapshot,
    category: IncidentCategory | str,
    severity: IncidentSeverity | str | None = None,
) -> RunbookSpec | None:
    cat = category if isinstance(category, IncidentCategory) else IncidentCategory.parse_category(category)
    sev = severity if severity is None or isinstance(severity, IncidentSeverity) else IncidentSeverity.parse_severity(severity)

    if sev is not None:
        for r in catalog.runbooks:
            if r.category == cat and r.severity == sev:
                return r
    for r in catalog.runbooks:
        if r.category == cat:
            return r
    return None

