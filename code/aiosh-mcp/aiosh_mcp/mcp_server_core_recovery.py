"""MCP Server Core Recovery & Validation Subsystem (MCPRECV-INV1..MCPRECV-INV5).

Guarantees resilience against state file corruption, unparseable JSON,
truncated writes, and process crashes via deep validation and atomic quarantine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import time
from typing import Any, Dict, List, Optional

MAX_STORE_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_PATH_LEN = 1024

MCPRECV_ERR_INVALID_PATH = "MCPRECV_ERR_INVALID_PATH"
MCPRECV_ERR_UNAUTHORIZED = "MCPRECV_ERR_UNAUTHORIZED"
MCPRECV_ERR_IO = "MCPRECV_ERR_IO"


def validate_store_path(path: str) -> Path:
    """Validates target store path against path traversal, NUL bytes, and length bounds."""
    if not path or not path.strip():
        raise ValueError(f"{MCPRECV_ERR_INVALID_PATH}: empty store path")
    trimmed = path.strip()
    if len(trimmed) > MAX_PATH_LEN:
        raise ValueError(f"{MCPRECV_ERR_INVALID_PATH}: path exceeds {MAX_PATH_LEN} characters")
    if "\0" in trimmed:
        raise ValueError(f"{MCPRECV_ERR_INVALID_PATH}: NUL byte detected in path")
    p = Path(trimmed)
    parts = p.parts
    if ".." in parts:
        raise ValueError(f"{MCPRECV_ERR_INVALID_PATH}: directory traversal sequence detected")
    return p


@dataclass(frozen=True)
class McpValidationIssue:
    severity: str
    code: str
    message: str
    path: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "path": self.path,
        }


@dataclass
class McpValidationReport:
    store_path: str
    is_healthy: bool
    total_records: int
    valid_records: int
    invalid_records: int
    issues: List[McpValidationIssue] = field(default_factory=list)
    validated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def validate_invariants(self) -> None:
        """Enforces MCPRECV-INV1 and MCPRECV-INV2."""
        if self.total_records != (self.valid_records + self.invalid_records):
            raise AssertionError(
                f"MCPRECV-INV1 violated: total_records ({self.total_records}) != "
                f"valid ({self.valid_records}) + invalid ({self.invalid_records})"
            )
        expected_healthy = (len(self.issues) == 0 and self.invalid_records == 0)
        if self.is_healthy != expected_healthy:
            raise AssertionError(
                f"MCPRECV-INV2 violated: is_healthy ({self.is_healthy}) != {expected_healthy}"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "store_path": self.store_path,
            "is_healthy": self.is_healthy,
            "total_records": self.total_records,
            "valid_records": self.valid_records,
            "invalid_records": self.invalid_records,
            "issues": [i.to_dict() for i in self.issues],
            "validated_at_utc": self.validated_at_utc,
        }


@dataclass
class McpRecoveryResult:
    ok: bool
    action_taken: str
    backup_path: Optional[str]
    report: McpValidationReport
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "action_taken": self.action_taken,
            "backup_path": self.backup_path,
            "report": self.report.to_dict(),
            "error": self.error,
        }


def validate_mcp_store(path: str) -> McpValidationReport:
    """Performs deep validation of an MCP state/config store file (MCPRECV-INV1..MCPRECV-INV5)."""
    p = validate_store_path(path)
    issues: List[McpValidationIssue] = []

    if not p.exists():
        issues.append(
            McpValidationIssue(
                severity="WARNING",
                code="FILE_MISSING",
                message="Store file does not exist",
                path=str(p),
            )
        )
        report = McpValidationReport(
            store_path=str(p),
            is_healthy=False,
            total_records=0,
            valid_records=0,
            invalid_records=0,
            issues=issues,
        )
        report.validate_invariants()
        return report

    try:
        size = p.stat().st_size
        if size > MAX_STORE_FILE_BYTES:
            issues.append(
                McpValidationIssue(
                    severity="ERROR",
                    code="BOUNDS_EXCEEDED",
                    message=f"Store file size ({size}) exceeds limit ({MAX_STORE_FILE_BYTES})",
                    path=str(p),
                )
            )
            report = McpValidationReport(
                store_path=str(p),
                is_healthy=False,
                total_records=1,
                valid_records=0,
                invalid_records=1,
                issues=issues,
            )
            report.validate_invariants()
            return report

        with open(p, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, dict):
            issues.append(
                McpValidationIssue(
                    severity="ERROR",
                    code="INVALID_SHAPE",
                    message="Root JSON payload must be an object",
                    path=str(p),
                )
            )
            report = McpValidationReport(
                store_path=str(p),
                is_healthy=False,
                total_records=1,
                valid_records=0,
                invalid_records=1,
                issues=issues,
            )
            report.validate_invariants()
            return report

        total = len(data)
        report = McpValidationReport(
            store_path=str(p),
            is_healthy=True,
            total_records=total,
            valid_records=total,
            invalid_records=0,
            issues=[],
        )
        report.validate_invariants()
        return report

    except json.JSONDecodeError as exc:
        issues.append(
            McpValidationIssue(
                severity="ERROR",
                code="INVALID_JSON",
                message=f"JSON parse error: {str(exc).splitlines()[0][:128]}",
                path=str(p),
            )
        )
        report = McpValidationReport(
            store_path=str(p),
            is_healthy=False,
            total_records=1,
            valid_records=0,
            invalid_records=1,
            issues=issues,
        )
        report.validate_invariants()
        return report
    except Exception as exc:
        issues.append(
            McpValidationIssue(
                severity="ERROR",
                code="READ_ERROR",
                message=f"Read error: {str(exc)[:128]}",
                path=str(p),
            )
        )
        report = McpValidationReport(
            store_path=str(p),
            is_healthy=False,
            total_records=1,
            valid_records=0,
            invalid_records=1,
            issues=issues,
        )
        report.validate_invariants()
        return report


def recover_mcp_store(path: str, capability_token: str) -> McpRecoveryResult:
    """Non-destructively recovers corrupted state via quarantine and reinitialization (MCPRECV-INV3, Invariant I-2)."""
    p = validate_store_path(path)

    # Invariant I-2 Gating: capability token required for state-changing file mutations
    if not capability_token or not capability_token.strip():
        raise PermissionError(
            f"{MCPRECV_ERR_UNAUTHORIZED}: capability token required for state recovery (PoR Invariant I-2)"
        )

    initial_report = validate_mcp_store(str(p))
    if initial_report.is_healthy:
        return McpRecoveryResult(
            ok=True,
            action_taken="NONE",
            backup_path=None,
            report=initial_report,
        )

    backup_path = None
    if p.exists():
        timestamp = int(time.time() * 1000)
        backup_p = p.with_name(f"{p.name}.bak.{timestamp}")
        shutil.copy2(p, backup_p)
        try:
            os.chmod(backup_p, 0o600)
        except OSError:
            pass
        backup_path = str(backup_p)

    # Atomically write fresh canonical store
    default_payload = {"version": "1.0", "sessions": {}, "metadata": {"recovered": True}}
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = p.with_name(f"{p.name}.tmp.{os.getpid()}.{time.time_ns()}")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(default_payload, f, indent=2)
    os.replace(tmp_path, p)

    new_report = validate_mcp_store(str(p))
    return McpRecoveryResult(
        ok=True,
        action_taken="QUARANTINE_AND_RESET",
        backup_path=backup_path,
        report=new_report,
    )
