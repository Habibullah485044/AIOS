"""Incident Response Runbooks Recovery & Validation Subsystem (IRREC1..IRREC5).

Provides non-destructive integrity checking, corrupted state quarantine,
snapshot restoration, and crash-consistent repair for Incident Response Runbooks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

IRREC_ERR_IO = "IRREC_ERR_IO"
IRREC_ERR_PARSE = "IRREC_ERR_PARSE"
IRREC_ERR_PATH_TRAVERSAL = "IRREC_ERR_PATH_TRAVERSAL"
IRREC_ERR_FILE_SIZE = "IRREC_ERR_FILE_SIZE"
IRREC_ERR_VALIDATION = "IRREC_ERR_VALIDATION"
IRREC_ERR_NO_BACKUP = "IRREC_ERR_NO_BACKUP"

MAX_RUNBOOK_STATE_SIZE = 10 * 1024 * 1024  # 10 MiB
MAX_QUARANTINE_FILES = 10
MAX_BACKUP_FILES = 10


class RunbookCatalogStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CORRUPTED = "corrupted"
    MISSING = "missing"


class RunbookIssueSeverity(str, Enum):
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class RunbookIssueType(str, Enum):
    MISSING_STATE_FILE = "missing_state_file"
    INVALID_JSON_SYNTAX = "invalid_json_syntax"
    INVALID_TOML_SYNTAX = "invalid_toml_syntax"
    SCHEMA_MISMATCH = "schema_mismatch"
    CORRUPTED_ENTRY = "corrupted_entry"
    DUPLICATE_RUNBOOK_ID = "duplicate_runbook_id"
    OVERSIZED_PAYLOAD = "oversized_payload"
    SYMLINK_FORBIDDEN = "symlink_forbidden"
    INVALID_PATH_TRAVERSAL = "invalid_path_traversal"
    EXCESSIVE_ACTIVE_SESSIONS = "excessive_active_sessions"


@dataclass
class RunbookValidationIssue:
    issue_type: RunbookIssueType
    severity: RunbookIssueSeverity
    message: str
    target_id: str | None = None


@dataclass
class RunbookValidationReport:
    status: RunbookCatalogStatus
    checked_at_utc: str
    target_path: str
    issues: list[RunbookValidationIssue] = field(default_factory=list)
    total_runbooks: int = 0
    total_active_sessions: int = 0
    is_recoverable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "checked_at_utc": self.checked_at_utc,
            "target_path": self.target_path,
            "issues": [
                {
                    "issue_type": i.issue_type.value,
                    "severity": i.severity.value,
                    "message": i.message,
                    "target_id": i.target_id,
                }
                for i in self.issues
            ],
            "total_runbooks": self.total_runbooks,
            "total_active_sessions": self.total_active_sessions,
            "is_recoverable": self.is_recoverable,
        }


@dataclass
class RunbookRecoveryReport:
    ok: bool
    recovered_at_utc: str
    quarantine_path: str | None = None
    backup_path: str | None = None
    restored_runbooks_count: int = 0
    action_taken: str = "noop"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "recovered_at_utc": self.recovered_at_utc,
            "quarantine_path": self.quarantine_path,
            "backup_path": self.backup_path,
            "restored_runbooks_count": self.restored_runbooks_count,
            "action_taken": self.action_taken,
        }


@dataclass
class RunbookRecoveryResultEnvelope:
    ok: bool
    data: Any | None = None
    error_code: str | None = None
    error_message: str | None = None
    audit_row_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "data": self.data,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "audit_row_required": self.audit_row_required,
        }

    @classmethod
    def success(cls, data: Any) -> RunbookRecoveryResultEnvelope:
        return cls(ok=True, data=data, audit_row_required=False)

    @classmethod
    def failure(cls, code: str, message: str) -> RunbookRecoveryResultEnvelope:
        return cls(ok=False, error_code=code, error_message=message, audit_row_required=True)


class RunbookRecoveryService:
    @classmethod
    def validate_state_path(cls, path: str | Path) -> RunbookValidationReport:
        raise NotImplementedError("Scaffold: validate_state_path implemented in T-03056")

    @classmethod
    def validate_runbook_json(cls, content: str) -> RunbookValidationReport:
        raise NotImplementedError("Scaffold: validate_runbook_json implemented in T-03056")

    @classmethod
    def repair_runbook_state(cls, path: str | Path) -> RunbookRecoveryReport:
        raise NotImplementedError("Scaffold: repair_runbook_state implemented in T-03056")

    @classmethod
    def create_snapshot(cls, path: str | Path, snapshot_dir: str | Path) -> str:
        raise NotImplementedError("Scaffold: create_snapshot implemented in T-03056")

    @classmethod
    def restore_snapshot(cls, snapshot_path: str | Path, target_path: str | Path) -> RunbookRecoveryReport:
        raise NotImplementedError("Scaffold: restore_snapshot implemented in T-03056")

    @classmethod
    def quarantine_corrupted_file(cls, path: str | Path) -> Path:
        raise NotImplementedError("Scaffold: quarantine_corrupted_file implemented in T-03056")

    @classmethod
    def rotate_quarantine_files(cls, directory: str | Path) -> int:
        raise NotImplementedError("Scaffold: rotate_quarantine_files implemented in T-03056")
