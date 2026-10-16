"""Incident Response Runbooks Recovery & Validation Subsystem (IRREC1..IRREC5).

Provides non-destructive integrity checking, corrupted state quarantine,
snapshot restoration, and crash-consistent repair for Incident Response Runbooks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import json
import os
from pathlib import Path
import time
from typing import Any

from .incident_runbook_data_model import RunbookCatalogSnapshot

IRREC_ERR_IO = "IRREC_ERR_IO"
IRREC_ERR_PARSE = "IRREC_ERR_PARSE"
IRREC_ERR_PATH_TRAVERSAL = "IRREC_ERR_PATH_TRAVERSAL"
IRREC_ERR_FILE_SIZE = "IRREC_ERR_FILE_SIZE"
IRREC_ERR_VALIDATION = "IRREC_ERR_VALIDATION"
IRREC_ERR_NO_BACKUP = "IRREC_ERR_NO_BACKUP"

MAX_RUNBOOK_STATE_SIZE = 10 * 1024 * 1024  # 10 MiB
MAX_QUARANTINE_FILES = 10
MAX_BACKUP_FILES = 10


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    def validate_path(cls, path: str | Path) -> Path:
        p_str = str(path).strip()
        if not p_str:
            raise ValueError(f"{IRREC_ERR_PATH_TRAVERSAL}: empty target path")
        if ".." in p_str or "\0" in p_str:
            raise ValueError(f"{IRREC_ERR_PATH_TRAVERSAL}: path traversal detected: '{p_str}'")
        return Path(p_str)

    @classmethod
    def backup_path_for(cls, path: str | Path) -> Path:
        p = Path(path)
        return p.with_name(f"{p.name}.bak")

    @classmethod
    def quarantine_path_for(cls, path: str | Path) -> Path:
        p = Path(path)
        parent = p.parent
        cls.prune_old_quarantine_files(parent, p.name)
        nanos = time.time_ns()
        pid = os.getpid()
        return parent / f"{p.name}.corrupt.{pid}.{nanos}"

    @classmethod
    def prune_old_quarantine_files(cls, parent: Path, base_fname: str) -> int:
        if not parent.exists():
            return 0
        prefix = f"{base_fname}.corrupt."
        entries = [
            parent / f
            for f in os.listdir(parent)
            if f.startswith(prefix) and (parent / f).is_file()
        ]
        if len(entries) <= MAX_QUARANTINE_FILES:
            return 0
        entries.sort(key=lambda p: p.stat().st_mtime)
        to_remove = len(entries) - MAX_QUARANTINE_FILES
        removed = 0
        for p in entries[:to_remove]:
            try:
                p.unlink()
                removed += 1
            except OSError:
                pass
        return removed

    @classmethod
    def validate_runbook_json(cls, content: str, target_path: str = "memory") -> RunbookValidationReport:
        now = _utcnow_iso()
        if len(content.encode("utf-8")) > MAX_RUNBOOK_STATE_SIZE:
            return RunbookValidationReport(
                status=RunbookCatalogStatus.CORRUPTED,
                checked_at_utc=now,
                target_path=target_path,
                issues=[
                    RunbookValidationIssue(
                        issue_type=RunbookIssueType.OVERSIZED_PAYLOAD,
                        severity=RunbookIssueSeverity.CRITICAL,
                        message=f"Payload size {len(content)} exceeds maximum limit {MAX_RUNBOOK_STATE_SIZE}",
                    )
                ],
                total_runbooks=0,
                is_recoverable=True,
            )

        try:
            raw = json.loads(content)
        except json.JSONDecodeError as exc:
            return RunbookValidationReport(
                status=RunbookCatalogStatus.CORRUPTED,
                checked_at_utc=now,
                target_path=target_path,
                issues=[
                    RunbookValidationIssue(
                        issue_type=RunbookIssueType.INVALID_JSON_SYNTAX,
                        severity=RunbookIssueSeverity.CRITICAL,
                        message=f"JSON decode error: {exc}",
                    )
                ],
                total_runbooks=0,
                is_recoverable=True,
            )

        if not isinstance(raw, dict) or "runbooks" not in raw:
            return RunbookValidationReport(
                status=RunbookCatalogStatus.CORRUPTED,
                checked_at_utc=now,
                target_path=target_path,
                issues=[
                    RunbookValidationIssue(
                        issue_type=RunbookIssueType.SCHEMA_MISMATCH,
                        severity=RunbookIssueSeverity.CRITICAL,
                        message="Missing top-level 'runbooks' array in catalog state",
                    )
                ],
                total_runbooks=0,
                is_recoverable=True,
            )

        runbooks_list = raw.get("runbooks", [])
        issues: list[RunbookValidationIssue] = []
        seen_ids: set[str] = set()

        for r in runbooks_list:
            if not isinstance(r, dict):
                issues.append(
                    RunbookValidationIssue(
                        issue_type=RunbookIssueType.CORRUPTED_ENTRY,
                        severity=RunbookIssueSeverity.CRITICAL,
                        message="Runbook entry is not an object",
                    )
                )
                continue
            rid = r.get("id")
            if not rid or not isinstance(rid, str):
                issues.append(
                    RunbookValidationIssue(
                        issue_type=RunbookIssueType.CORRUPTED_ENTRY,
                        severity=RunbookIssueSeverity.CRITICAL,
                        message="Runbook entry missing valid 'id'",
                    )
                )
                continue
            if rid in seen_ids:
                issues.append(
                    RunbookValidationIssue(
                        issue_type=RunbookIssueType.DUPLICATE_RUNBOOK_ID,
                        severity=RunbookIssueSeverity.ERROR,
                        message=f"Duplicate runbook ID detected: '{rid}'",
                        target_id=rid,
                    )
                )
            seen_ids.add(rid)

            steps = r.get("steps")
            if not steps or not isinstance(steps, list):
                issues.append(
                    RunbookValidationIssue(
                        issue_type=RunbookIssueType.CORRUPTED_ENTRY,
                        severity=RunbookIssueSeverity.ERROR,
                        message=f"Runbook '{rid}' has empty or invalid step list",
                        target_id=rid,
                    )
                )

        status = RunbookCatalogStatus.HEALTHY
        if any(i.severity == RunbookIssueSeverity.CRITICAL for i in issues):
            status = RunbookCatalogStatus.CORRUPTED
        elif any(i.severity == RunbookIssueSeverity.ERROR for i in issues):
            status = RunbookCatalogStatus.DEGRADED

        return RunbookValidationReport(
            status=status,
            checked_at_utc=now,
            target_path=target_path,
            issues=issues,
            total_runbooks=len(runbooks_list),
            is_recoverable=True,
        )

    @classmethod
    def validate_state_path(cls, path: str | Path) -> RunbookValidationReport:
        now = _utcnow_iso()
        try:
            valid_path = cls.validate_path(path)
        except ValueError as exc:
            return RunbookValidationReport(
                status=RunbookCatalogStatus.CORRUPTED,
                checked_at_utc=now,
                target_path=str(path),
                issues=[
                    RunbookValidationIssue(
                        issue_type=RunbookIssueType.INVALID_PATH_TRAVERSAL,
                        severity=RunbookIssueSeverity.CRITICAL,
                        message=str(exc),
                    )
                ],
                is_recoverable=False,
            )

        if not valid_path.exists():
            return RunbookValidationReport(
                status=RunbookCatalogStatus.MISSING,
                checked_at_utc=now,
                target_path=str(valid_path),
                issues=[
                    RunbookValidationIssue(
                        issue_type=RunbookIssueType.MISSING_STATE_FILE,
                        severity=RunbookIssueSeverity.CRITICAL,
                        message=f"Runbook state file does not exist: {valid_path}",
                    )
                ],
                is_recoverable=True,
            )

        try:
            st = valid_path.stat()
            if st.st_size > MAX_RUNBOOK_STATE_SIZE:
                return RunbookValidationReport(
                    status=RunbookCatalogStatus.CORRUPTED,
                    checked_at_utc=now,
                    target_path=str(valid_path),
                    issues=[
                        RunbookValidationIssue(
                            issue_type=RunbookIssueType.OVERSIZED_PAYLOAD,
                            severity=RunbookIssueSeverity.CRITICAL,
                            message=f"File size {st.st_size} exceeds limit {MAX_RUNBOOK_STATE_SIZE}",
                        )
                    ],
                    is_recoverable=True,
                )
            content = valid_path.read_text(encoding="utf-8")
        except Exception as exc:
            return RunbookValidationReport(
                status=RunbookCatalogStatus.CORRUPTED,
                checked_at_utc=now,
                target_path=str(valid_path),
                issues=[
                    RunbookValidationIssue(
                        issue_type=RunbookIssueType.INVALID_JSON_SYNTAX,
                        severity=RunbookIssueSeverity.CRITICAL,
                        message=f"Failed reading file content: {exc}",
                    )
                ],
                is_recoverable=True,
            )

        return cls.validate_runbook_json(content, target_path=str(valid_path))

    @classmethod
    def atomic_write_file(cls, target: Path, content: str | bytes) -> None:
        parent = target.parent
        parent.mkdir(parents=True, exist_ok=True)
        nanos = time.time_ns()
        pid = os.getpid()
        tmp_path = parent / f".{target.name}.tmp.{pid}.{nanos}"
        data = content.encode("utf-8") if isinstance(content, str) else content
        try:
            with open(tmp_path, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, target)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    @classmethod
    def quarantine_corrupted_file(cls, path: str | Path) -> Path:
        valid_path = cls.validate_path(path)
        if not valid_path.exists():
            raise FileNotFoundError(f"{IRREC_ERR_IO}: cannot quarantine missing file: {valid_path}")
        q_path = cls.quarantine_path_for(valid_path)
        content = valid_path.read_bytes()
        cls.atomic_write_file(q_path, content)
        return q_path

    @classmethod
    def create_backup(cls, path: str | Path) -> Path:
        valid_path = cls.validate_path(path)
        if not valid_path.exists():
            raise FileNotFoundError(f"{IRREC_ERR_IO}: source file missing: {valid_path}")
        b_path = cls.backup_path_for(valid_path)
        content = valid_path.read_bytes()
        cls.atomic_write_file(b_path, content)
        return b_path

    @classmethod
    def restore_snapshot(cls, snapshot_path: str | Path, target_path: str | Path) -> RunbookRecoveryReport:
        v_snap = cls.validate_path(snapshot_path)
        v_target = cls.validate_path(target_path)

        if not v_snap.exists():
            raise FileNotFoundError(f"{IRREC_ERR_NO_BACKUP}: snapshot missing: {v_snap}")

        snap_report = cls.validate_state_path(v_snap)
        if snap_report.status == RunbookCatalogStatus.CORRUPTED:
            raise ValueError(f"{IRREC_ERR_VALIDATION}: corrupted snapshot cannot be restored")

        q_path = None
        if v_target.exists():
            try:
                q_path = str(cls.quarantine_corrupted_file(v_target))
            except Exception:
                pass

        content = v_snap.read_bytes()
        cls.atomic_write_file(v_target, content)

        return RunbookRecoveryReport(
            ok=True,
            recovered_at_utc=_utcnow_iso(),
            quarantine_path=q_path,
            backup_path=str(v_snap),
            restored_runbooks_count=snap_report.total_runbooks,
            action_taken="backup_restored",
        )

    @classmethod
    def repair_runbook_state(cls, path: str | Path) -> RunbookRecoveryReport:
        valid_path = cls.validate_path(path)
        report = cls.validate_state_path(valid_path)

        if report.status == RunbookCatalogStatus.HEALTHY:
            return RunbookRecoveryReport(
                ok=True,
                recovered_at_utc=_utcnow_iso(),
                quarantine_path=None,
                backup_path=None,
                restored_runbooks_count=report.total_runbooks,
                action_taken="noop",
            )

        if report.status == RunbookCatalogStatus.MISSING:
            canonical = RunbookCatalogSnapshot.canonical_baseline()
            # serialize
            content = json.dumps(
                {
                    "catalog_version": canonical.catalog_version,
                    "runbooks": [
                        {
                            "id": r.id,
                            "title": r.title,
                            "category": r.category.value,
                            "severity": r.severity.value,
                            "description": r.description,
                            "tags": r.tags,
                            "steps": [
                                {
                                    "id": s.id,
                                    "title": s.title,
                                    "phase": s.phase.value,
                                    "target": s.target.value,
                                    "action_template": s.action_template,
                                    "automated": s.automated,
                                    "requires_confirmation": s.requires_confirmation,
                                    "timeout_seconds": s.timeout_seconds,
                                }
                                for s in r.steps
                            ],
                        }
                        for r in canonical.runbooks
                    ],
                },
                indent=2,
            )
            cls.atomic_write_file(valid_path, content)
            return RunbookRecoveryReport(
                ok=True,
                recovered_at_utc=_utcnow_iso(),
                quarantine_path=None,
                backup_path=None,
                restored_runbooks_count=len(canonical.runbooks),
                action_taken="canonical_reinitialized",
            )

        # Corrupted or Degraded
        q_path = None
        if valid_path.exists():
            try:
                q_path = str(cls.quarantine_corrupted_file(valid_path))
            except Exception:
                pass

        b_path = cls.backup_path_for(valid_path)
        if b_path.exists():
            b_report = cls.validate_state_path(b_path)
            if b_report.status == RunbookCatalogStatus.HEALTHY:
                content = b_path.read_bytes()
                cls.atomic_write_file(valid_path, content)
                return RunbookRecoveryReport(
                    ok=True,
                    recovered_at_utc=_utcnow_iso(),
                    quarantine_path=q_path,
                    backup_path=str(b_path),
                    restored_runbooks_count=b_report.total_runbooks,
                    action_taken="backup_restored",
                )

        # Fallback to canonical baseline
        canonical = RunbookCatalogSnapshot.canonical_baseline()
        content = json.dumps(
            {
                "catalog_version": canonical.catalog_version,
                "runbooks": [
                    {
                        "id": r.id,
                        "title": r.title,
                        "category": r.category.value,
                        "severity": r.severity.value,
                        "description": r.description,
                        "tags": r.tags,
                        "steps": [
                            {
                                "id": s.id,
                                "title": s.title,
                                "phase": s.phase.value,
                                "target": s.target.value,
                                "action_template": s.action_template,
                                "automated": s.automated,
                                "requires_confirmation": s.requires_confirmation,
                                "timeout_seconds": s.timeout_seconds,
                            }
                            for s in r.steps
                        ],
                    }
                    for r in canonical.runbooks
                ],
            },
            indent=2,
        )
        cls.atomic_write_file(valid_path, content)
        return RunbookRecoveryReport(
            ok=True,
            recovered_at_utc=_utcnow_iso(),
            quarantine_path=q_path,
            backup_path=None,
            restored_runbooks_count=len(canonical.runbooks),
            action_taken="canonical_reinitialized",
        )
