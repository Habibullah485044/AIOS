"""Compliance Mapping Recovery & Integrity Validation (COMPLYREC1..COMPLYREC5).

Provides integrity checking, corrupt catalog quarantine, snapshot backup,
and crash-consistent repair for the AIOS compliance catalog.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

COMPLYREC_ERR_IO = "COMPLYREC_ERR_IO"
COMPLYREC_ERR_PARSE = "COMPLYREC_ERR_PARSE"
COMPLYREC_ERR_PATH_TRAVERSAL = "COMPLYREC_ERR_PATH_TRAVERSAL"
COMPLYREC_ERR_FILE_SIZE = "COMPLYREC_ERR_FILE_SIZE"
COMPLYREC_ERR_VALIDATION = "COMPLYREC_ERR_VALIDATION"
COMPLYREC_ERR_NO_BACKUP = "COMPLYREC_ERR_NO_BACKUP"


class ComplianceCatalogStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CORRUPTED = "corrupted"
    MISSING = "missing"


class ComplianceIssueSeverity(str, Enum):
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ComplianceIssueType(str, Enum):
    MISSING_CATALOG_FILE = "missing_catalog_file"
    INVALID_JSON_SYNTAX = "invalid_json_syntax"
    SCHEMA_MISMATCH = "schema_mismatch"
    CORRUPTED_ENTRY = "corrupted_entry"
    DUPLICATE_MAPPING_ID = "duplicate_mapping_id"
    OVERSIZED_PAYLOAD = "oversized_payload"
    SYMLINK_FORBIDDEN = "symlink_forbidden"
    INVALID_PATH_TRAVERSAL = "invalid_path_traversal"
    INVALID_TIMESTAMP = "invalid_timestamp"


@dataclass
class ComplianceIntegrityIssue:
    severity: ComplianceIssueSeverity
    issue_type: ComplianceIssueType
    mapping_id: str | None
    details: str


@dataclass
class ComplianceIntegrityReport:
    store_path: str
    status: ComplianceCatalogStatus
    total_mappings: int
    valid_mappings: int
    corrupted_mappings: int
    issues: list[ComplianceIntegrityIssue] = field(default_factory=list)
    has_backup: bool = False
    backup_path: str | None = None
    timestamp: str = ""


@dataclass
class ComplianceRecoveryAction:
    action_type: str
    target_id: str | None
    description: str


@dataclass
class ComplianceRecoveryReport:
    store_path: str
    success: bool
    actions: list[ComplianceRecoveryAction] = field(default_factory=list)
    mappings_recovered: int = 0
    mappings_dropped: int = 0
    quarantined_path: str | None = None
    timestamp: str = ""


class ComplianceRecoveryService:
    @classmethod
    def validate_path(cls, path: Path | str) -> Path:
        # Scaffold stub (T-02955)
        raise NotImplementedError("ComplianceRecoveryService.validate_path scaffolded for T-02955")

    @classmethod
    def verify_integrity(cls, path: Path | str) -> ComplianceIntegrityReport:
        # Scaffold stub (T-02955)
        raise NotImplementedError("ComplianceRecoveryService.verify_integrity scaffolded for T-02955")

    @classmethod
    def create_backup(cls, path: Path | str) -> Path:
        # Scaffold stub (T-02955)
        raise NotImplementedError("ComplianceRecoveryService.create_backup scaffolded for T-02955")

    @classmethod
    def repair_catalog(cls, path: Path | str) -> ComplianceRecoveryReport:
        # Scaffold stub (T-02955)
        raise NotImplementedError("ComplianceRecoveryService.repair_catalog scaffolded for T-02955")

    @classmethod
    def restore_from_backup(cls, path: Path | str) -> ComplianceRecoveryReport:
        # Scaffold stub (T-02955)
        raise NotImplementedError("ComplianceRecoveryService.restore_from_backup scaffolded for T-02955")
