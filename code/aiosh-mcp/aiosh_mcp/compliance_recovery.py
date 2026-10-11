"""Compliance Mapping Recovery & Integrity Validation (COMPLYREC1..COMPLYREC5).

Provides integrity checking, corrupt catalog quarantine, snapshot backup,
and crash-consistent repair for the AIOS compliance catalog.
"""

from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from .audit_client import utcnow_iso

COMPLYREC_ERR_IO = "COMPLYREC_ERR_IO"
COMPLYREC_ERR_PARSE = "COMPLYREC_ERR_PARSE"
COMPLYREC_ERR_PATH_TRAVERSAL = "COMPLYREC_ERR_PATH_TRAVERSAL"
COMPLYREC_ERR_FILE_SIZE = "COMPLYREC_ERR_FILE_SIZE"
COMPLYREC_ERR_VALIDATION = "COMPLYREC_ERR_VALIDATION"
COMPLYREC_ERR_NO_BACKUP = "COMPLYREC_ERR_NO_BACKUP"

MAX_COMPLIANCE_STORE_SIZE = 1024 * 1024  # 1 MiB


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
        p_str = str(path).strip()
        if not p_str:
            raise ValueError(f"{COMPLYREC_ERR_PATH_TRAVERSAL}: Path cannot be empty")
        if ".." in p_str or p_str.startswith("\\\\") or p_str.startswith("//") or any(ord(c) < 32 for c in p_str):
            raise ValueError(f"{COMPLYREC_ERR_PATH_TRAVERSAL}: Path contains forbidden traversal or control characters: {p_str}")
        p = Path(path)
        if len(p.parts) > 16:
            raise ValueError(f"{COMPLYREC_ERR_PATH_TRAVERSAL}: Path depth exceeds maximum allowed of 16")
        if p.is_symlink():
            raise ValueError(f"{COMPLYREC_ERR_PATH_TRAVERSAL}: Symlinks are forbidden: {p_str}")
        return p

    @classmethod
    def backup_path_for(cls, path: Path) -> Path:
        return path.with_name(path.name + ".bak")

    @classmethod
    def quarantine_path_for(cls, path: Path) -> Path:
        nanos = int(time.time() * 1_000_000_000)
        pid = os.getpid()
        return path.with_name(f"{path.name}.corrupt.{pid}.{nanos}")

    @classmethod
    def create_backup(cls, path: Path | str) -> Path:
        valid_path = cls.validate_path(path)
        if not valid_path.exists():
            raise ValueError(f"{COMPLYREC_ERR_IO}: Target file does not exist: {valid_path}")
        backup_path = cls.backup_path_for(valid_path)
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(valid_path, backup_path)
        return backup_path

    @classmethod
    def verify_integrity(cls, path: Path | str) -> ComplianceIntegrityReport:
        try:
            valid_path = cls.validate_path(path)
        except ValueError as exc:
            return ComplianceIntegrityReport(
                store_path=str(path),
                status=ComplianceCatalogStatus.CORRUPTED,
                total_mappings=0,
                valid_mappings=0,
                corrupted_mappings=0,
                issues=[
                    ComplianceIntegrityIssue(
                        severity=ComplianceIssueSeverity.CRITICAL,
                        issue_type=ComplianceIssueType.INVALID_PATH_TRAVERSAL,
                        mapping_id=None,
                        details=str(exc),
                    )
                ],
                has_backup=False,
                backup_path=None,
                timestamp=utcnow_iso(),
            )

        backup_p = cls.backup_path_for(valid_path)
        has_backup = backup_p.exists()
        backup_str = str(backup_p) if has_backup else None

        if not valid_path.exists():
            return ComplianceIntegrityReport(
                store_path=str(valid_path),
                status=ComplianceCatalogStatus.MISSING,
                total_mappings=0,
                valid_mappings=0,
                corrupted_mappings=0,
                issues=[
                    ComplianceIntegrityIssue(
                        severity=ComplianceIssueSeverity.WARNING,
                        issue_type=ComplianceIssueType.MISSING_CATALOG_FILE,
                        mapping_id=None,
                        details="Compliance map store file does not exist",
                    )
                ],
                has_backup=has_backup,
                backup_path=backup_str,
                timestamp=utcnow_iso(),
            )

        try:
            file_size = valid_path.stat().st_size
        except OSError as exc:
            return ComplianceIntegrityReport(
                store_path=str(valid_path),
                status=ComplianceCatalogStatus.CORRUPTED,
                total_mappings=0,
                valid_mappings=0,
                corrupted_mappings=0,
                issues=[
                    ComplianceIntegrityIssue(
                        severity=ComplianceIssueSeverity.CRITICAL,
                        issue_type=ComplianceIssueType.INVALID_JSON_SYNTAX,
                        mapping_id=None,
                        details=f"Stat error: {exc}",
                    )
                ],
                has_backup=has_backup,
                backup_path=backup_str,
                timestamp=utcnow_iso(),
            )

        if file_size > MAX_COMPLIANCE_STORE_SIZE:
            return ComplianceIntegrityReport(
                store_path=str(valid_path),
                status=ComplianceCatalogStatus.CORRUPTED,
                total_mappings=0,
                valid_mappings=0,
                corrupted_mappings=0,
                issues=[
                    ComplianceIntegrityIssue(
                        severity=ComplianceIssueSeverity.CRITICAL,
                        issue_type=ComplianceIssueType.OVERSIZED_PAYLOAD,
                        mapping_id=None,
                        details=f"File size {file_size} exceeds maximum allowed {MAX_COMPLIANCE_STORE_SIZE}",
                    )
                ],
                has_backup=has_backup,
                backup_path=backup_str,
                timestamp=utcnow_iso(),
            )

        try:
            with open(valid_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            return ComplianceIntegrityReport(
                store_path=str(valid_path),
                status=ComplianceCatalogStatus.CORRUPTED,
                total_mappings=0,
                valid_mappings=0,
                corrupted_mappings=0,
                issues=[
                    ComplianceIntegrityIssue(
                        severity=ComplianceIssueSeverity.CRITICAL,
                        issue_type=ComplianceIssueType.INVALID_JSON_SYNTAX,
                        mapping_id=None,
                        details=f"JSON parse error: {exc}",
                    )
                ],
                has_backup=has_backup,
                backup_path=backup_str,
                timestamp=utcnow_iso(),
            )

        if not isinstance(data, dict) or "mappings" not in data or not isinstance(data["mappings"], list):
            return ComplianceIntegrityReport(
                store_path=str(valid_path),
                status=ComplianceCatalogStatus.CORRUPTED,
                total_mappings=0,
                valid_mappings=0,
                corrupted_mappings=0,
                issues=[
                    ComplianceIntegrityIssue(
                        severity=ComplianceIssueSeverity.CRITICAL,
                        issue_type=ComplianceIssueType.SCHEMA_MISMATCH,
                        mapping_id=None,
                        details="Root object missing 'mappings' array",
                    )
                ],
                has_backup=has_backup,
                backup_path=backup_str,
                timestamp=utcnow_iso(),
            )

        issues: list[ComplianceIntegrityIssue] = []
        seen_ids: set[str] = set()
        valid_count = 0
        corrupted_count = 0

        for entry in data["mappings"]:
            if not isinstance(entry, dict):
                corrupted_count += 1
                issues.append(
                    ComplianceIntegrityIssue(
                        severity=ComplianceIssueSeverity.ERROR,
                        issue_type=ComplianceIssueType.CORRUPTED_ENTRY,
                        mapping_id=None,
                        details="Mapping item is not a dictionary",
                    )
                )
                continue

            entry_id = entry.get("id")
            if not isinstance(entry_id, str) or not entry_id.strip():
                corrupted_count += 1
                issues.append(
                    ComplianceIntegrityIssue(
                        severity=ComplianceIssueSeverity.ERROR,
                        issue_type=ComplianceIssueType.CORRUPTED_ENTRY,
                        mapping_id=str(entry_id),
                        details="Invalid or missing mapping ID",
                    )
                )
                continue

            if entry_id in seen_ids:
                corrupted_count += 1
                issues.append(
                    ComplianceIntegrityIssue(
                        severity=ComplianceIssueSeverity.ERROR,
                        issue_type=ComplianceIssueType.DUPLICATE_MAPPING_ID,
                        mapping_id=entry_id,
                        details=f"Duplicate mapping ID: {entry_id}",
                    )
                )
                continue
            seen_ids.add(entry_id)

            control_id = entry.get("control_id")
            target_ref = entry.get("target_ref")
            if not control_id or not str(control_id).strip() or not target_ref or not str(target_ref).strip():
                corrupted_count += 1
                issues.append(
                    ComplianceIntegrityIssue(
                        severity=ComplianceIssueSeverity.ERROR,
                        issue_type=ComplianceIssueType.CORRUPTED_ENTRY,
                        mapping_id=entry_id,
                        details="Empty control_id or target_ref",
                    )
                )
                continue

            valid_count += 1

        total = len(data["mappings"])
        if not issues:
            status = ComplianceCatalogStatus.HEALTHY
        elif valid_count > 0:
            status = ComplianceCatalogStatus.DEGRADED
        else:
            status = ComplianceCatalogStatus.CORRUPTED

        return ComplianceIntegrityReport(
            store_path=str(valid_path),
            status=status,
            total_mappings=total,
            valid_mappings=valid_count,
            corrupted_mappings=corrupted_count,
            issues=issues,
            has_backup=has_backup,
            backup_path=backup_str,
            timestamp=utcnow_iso(),
        )

    @classmethod
    def repair_catalog(cls, path: Path | str) -> ComplianceRecoveryReport:
        valid_path = cls.validate_path(path)
        from .compliance import canonical_baseline, save_store

        if not valid_path.exists():
            snap = canonical_baseline()
            save_store(str(valid_path), snap)
            return ComplianceRecoveryReport(
                store_path=str(valid_path),
                success=True,
                actions=[
                    ComplianceRecoveryAction(
                        action_type="seed_canonical",
                        target_id=None,
                        description="Missing file recreated with canonical compliance catalog",
                    )
                ],
                mappings_recovered=len(snap.mappings),
                mappings_dropped=0,
                quarantined_path=None,
                timestamp=utcnow_iso(),
            )

        quarantine_p = cls.quarantine_path_for(valid_path)
        shutil.copy2(valid_path, quarantine_p)

        actions: list[ComplianceRecoveryAction] = [
            ComplianceRecoveryAction(
                action_type="quarantine",
                target_id=None,
                description=f"Original store quarantined to {quarantine_p}",
            )
        ]

        try:
            with open(valid_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = None

        from .compliance import ComplianceCatalogSnapshot, ComplianceMappingEntry

        salvaged_entries: list[ComplianceMappingEntry] = []
        dropped_count = 0

        if isinstance(data, dict) and "mappings" in data and isinstance(data["mappings"], list):
            seen_ids: set[str] = set()
            for m in data["mappings"]:
                if isinstance(m, dict) and m.get("id") and str(m["id"]).strip() not in seen_ids and m.get("control_id") and m.get("target_ref"):
                    try:
                        entry = ComplianceMappingEntry(
                            id=m["id"],
                            control_id=m["control_id"],
                            framework=m.get("framework", "nist_sp_800_53_rev5"),
                            target_type=m.get("target_type", "pep_gate"),
                            target_ref=m["target_ref"],
                            threat_ids=m.get("threat_ids", []),
                            status=m.get("status", "non_compliant"),
                            mitigation_summary=m.get("mitigation_summary", ""),
                            tags=m.get("tags", []),
                            created_at=m.get("created_at", utcnow_iso()),
                            updated_at=m.get("updated_at", utcnow_iso()),
                        )
                        salvaged_entries.append(entry)
                        seen_ids.add(m["id"])
                    except Exception:
                        dropped_count += 1
                else:
                    dropped_count += 1
                    actions.append(
                        ComplianceRecoveryAction(
                            action_type="drop_corrupted_entry",
                            target_id=m.get("id") if isinstance(m, dict) else None,
                            description=f"Dropped corrupted mapping entry {m.get('id') if isinstance(m, dict) else 'unknown'}",
                        )
                    )
        else:
            base = canonical_baseline()
            salvaged_entries = base.mappings
            actions.append(
                ComplianceRecoveryAction(
                    action_type="fallback_canonical",
                    target_id=None,
                    description="Unparseable JSON repaired using canonical compliance baseline",
                )
            )

        snap = ComplianceCatalogSnapshot(
            version="1.0.0",
            mappings=salvaged_entries,
            generated_at=utcnow_iso(),
        )
        save_store(str(valid_path), snap)

        actions.append(
            ComplianceRecoveryAction(
                action_type="atomic_write",
                target_id=None,
                description=f"Clean catalog persisted with {len(salvaged_entries)} entries",
            )
        )

        return ComplianceRecoveryReport(
            store_path=str(valid_path),
            success=True,
            actions=actions,
            mappings_recovered=len(salvaged_entries),
            mappings_dropped=dropped_count,
            quarantined_path=str(quarantine_p),
            timestamp=utcnow_iso(),
        )

    @classmethod
    def restore_from_backup(cls, path: Path | str) -> ComplianceRecoveryReport:
        valid_path = cls.validate_path(path)
        backup_path = cls.backup_path_for(valid_path)

        if not backup_path.exists():
            raise ValueError(f"{COMPLYREC_ERR_NO_BACKUP}: Backup file not found: {backup_path}")

        backup_report = cls.verify_integrity(backup_path)
        if backup_report.status == ComplianceCatalogStatus.CORRUPTED:
            raise ValueError(f"{COMPLYREC_ERR_VALIDATION}: Backup file is itself corrupted: {backup_report.issues}")

        quarantined = None
        if valid_path.exists():
            q_path = cls.quarantine_path_for(valid_path)
            shutil.copy2(valid_path, q_path)
            quarantined = str(q_path)

        shutil.copy2(backup_path, valid_path)
        restored_report = cls.verify_integrity(valid_path)

        return ComplianceRecoveryReport(
            store_path=str(valid_path),
            success=True,
            actions=[
                ComplianceRecoveryAction(
                    action_type="restore_from_backup",
                    target_id=None,
                    description=f"Restored store from {backup_path}",
                )
            ],
            mappings_recovered=restored_report.valid_mappings,
            mappings_dropped=0,
            quarantined_path=quarantined,
            timestamp=utcnow_iso(),
        )
