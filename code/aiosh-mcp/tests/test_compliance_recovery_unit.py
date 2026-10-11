"""Unit tests for Compliance Mapping Recovery and Validation (T-02957)."""

import json
from pathlib import Path
import pytest

from aiosh_mcp.compliance_recovery import (
    ComplianceRecoveryService,
    ComplianceCatalogStatus,
    ComplianceIssueSeverity,
    ComplianceIssueType,
    COMPLYREC_ERR_PATH_TRAVERSAL,
    COMPLYREC_ERR_FILE_SIZE,
    COMPLYREC_ERR_NO_BACKUP,
    MAX_COMPLIANCE_STORE_SIZE,
)


def test_recovery_unit_verify_healthy_catalog(tmp_path: Path):
    store_file = tmp_path / "compliance_store.json"
    catalog_data = {
        "version": "1.0.0",
        "generated_at": "2026-10-11T00:00:00Z",
        "mappings": [
            {
                "id": "MAP-REC-01",
                "control_id": "AC-1",
                "framework": "nist_sp_800_53_rev5",
                "target_type": "pep_gate",
                "target_ref": "kernel.pep.gate",
                "threat_ids": ["T-01"],
                "status": "compliant",
                "mitigation_summary": "Mitigation applied",
                "tags": ["recovery"],
                "created_at": "2026-10-11T00:00:00Z",
                "updated_at": "2026-10-11T00:00:00Z",
            }
        ],
    }
    store_file.write_text(json.dumps(catalog_data), encoding="utf-8")

    report = ComplianceRecoveryService.verify_integrity(store_file)

    assert report.status == ComplianceCatalogStatus.HEALTHY
    assert report.valid_mappings == 1
    assert report.corrupted_mappings == 0
    assert len(report.issues) == 0


def test_recovery_unit_verify_missing_file(tmp_path: Path):
    missing_file = tmp_path / "nonexistent.json"
    report = ComplianceRecoveryService.verify_integrity(missing_file)

    assert report.status == ComplianceCatalogStatus.MISSING
    assert report.valid_mappings == 0
    assert len(report.issues) > 0
    assert any(i.issue_type == ComplianceIssueType.MISSING_CATALOG_FILE for i in report.issues)


def test_recovery_unit_verify_corrupted_json(tmp_path: Path):
    corrupt_file = tmp_path / "corrupt.json"
    corrupt_file.write_text("{ unclosed bad json content...", encoding="utf-8")

    report = ComplianceRecoveryService.verify_integrity(corrupt_file)

    assert report.status == ComplianceCatalogStatus.CORRUPTED
    assert any(i.issue_type == ComplianceIssueType.INVALID_JSON_SYNTAX for i in report.issues)


def test_recovery_unit_path_traversal_rejection(tmp_path: Path):
    traversal_path = "../secret.json"
    with pytest.raises(ValueError) as excinfo:
        ComplianceRecoveryService.validate_path(traversal_path)

    assert COMPLYREC_ERR_PATH_TRAVERSAL in str(excinfo.value)


def test_recovery_unit_create_backup_and_restore(tmp_path: Path):
    store_file = tmp_path / "compliance_store.json"
    catalog_data = {
        "version": "1.0.0",
        "generated_at": "2026-10-11T00:00:00Z",
        "mappings": [
            {
                "id": "MAP-RESTORE-01",
                "control_id": "AC-2",
                "framework": "soc2_type2",
                "target_type": "capability_token",
                "target_ref": "token.grant",
                "threat_ids": [],
                "status": "compliant",
                "mitigation_summary": "Mitigated",
                "tags": [],
                "created_at": "2026-10-11T00:00:00Z",
                "updated_at": "2026-10-11T00:00:00Z",
            }
        ],
    }
    store_file.write_text(json.dumps(catalog_data), encoding="utf-8")

    backup_path = ComplianceRecoveryService.create_backup(store_file)
    assert backup_path.exists()

    # Corrupt store file
    store_file.write_text("corrupted", encoding="utf-8")
    assert ComplianceRecoveryService.verify_integrity(store_file).status == ComplianceCatalogStatus.CORRUPTED

    # Restore
    restore_report = ComplianceRecoveryService.restore_from_backup(store_file)
    assert restore_report.success

    # Verify restored content
    report = ComplianceRecoveryService.verify_integrity(store_file)
    assert report.status == ComplianceCatalogStatus.HEALTHY
    assert report.valid_mappings == 1


def test_recovery_unit_repair_catalog(tmp_path: Path):
    store_file = tmp_path / "repair.json"
    partially_corrupt = {
        "version": "1.0.0",
        "generated_at": "2026-10-11T00:00:00Z",
        "mappings": [
            {
                "id": "MAP-GOOD-01",
                "control_id": "AU-2",
                "framework": "nist_sp_800_53_rev5",
                "target_type": "audit_ring",
                "target_ref": "audit.ring",
                "threat_ids": [],
                "status": "compliant",
                "mitigation_summary": "Audit ring logging enabled",
                "tags": [],
                "created_at": "2026-10-11T00:00:00Z",
                "updated_at": "2026-10-11T00:00:00Z",
            },
            {
                "id": "MAP-BAD-02",
                "control_id": "",
                "framework": "nist_sp_800_53_rev5",
                "target_type": "audit_ring",
                "target_ref": "",
                "threat_ids": [],
                "status": "non_compliant",
                "mitigation_summary": "",
                "tags": [],
                "created_at": "2026-10-11T00:00:00Z",
                "updated_at": "2026-10-11T00:00:00Z",
            },
        ],
    }
    store_file.write_text(json.dumps(partially_corrupt), encoding="utf-8")

    repair_report = ComplianceRecoveryService.repair_catalog(store_file)

    assert repair_report.success
    assert repair_report.mappings_recovered == 1
    assert repair_report.mappings_dropped == 1

    # Verify
    report = ComplianceRecoveryService.verify_integrity(store_file)
    assert report.status == ComplianceCatalogStatus.HEALTHY
    assert report.valid_mappings == 1
