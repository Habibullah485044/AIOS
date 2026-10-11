"""Scaffold verification tests for Compliance Mapping Recovery & Validation (T-02955)."""

from pathlib import Path
import pytest

from aiosh_mcp.compliance import execute
from aiosh_mcp.compliance_recovery import (
    COMPLYREC_ERR_FILE_SIZE,
    COMPLYREC_ERR_IO,
    COMPLYREC_ERR_NO_BACKUP,
    COMPLYREC_ERR_PARSE,
    COMPLYREC_ERR_PATH_TRAVERSAL,
    COMPLYREC_ERR_VALIDATION,
    ComplianceCatalogStatus,
    ComplianceIssueSeverity,
    ComplianceIssueType,
    ComplianceRecoveryService,
)


def test_compliance_recovery_scaffold_constants_and_types() -> None:
    assert COMPLYREC_ERR_IO == "COMPLYREC_ERR_IO"
    assert COMPLYREC_ERR_PARSE == "COMPLYREC_ERR_PARSE"
    assert COMPLYREC_ERR_PATH_TRAVERSAL == "COMPLYREC_ERR_PATH_TRAVERSAL"
    assert COMPLYREC_ERR_FILE_SIZE == "COMPLYREC_ERR_FILE_SIZE"
    assert COMPLYREC_ERR_VALIDATION == "COMPLYREC_ERR_VALIDATION"
    assert COMPLYREC_ERR_NO_BACKUP == "COMPLYREC_ERR_NO_BACKUP"

    assert ComplianceCatalogStatus.HEALTHY.value == "healthy"
    assert ComplianceIssueSeverity.CRITICAL.value == "critical"
    assert ComplianceIssueType.SCHEMA_MISMATCH.value == "schema_mismatch"


def test_compliance_recovery_scaffold_loud_failure_stubs() -> None:
    dummy_path = Path("dummy/path.json")

    with pytest.raises(NotImplementedError):
        ComplianceRecoveryService.validate_path(dummy_path)

    with pytest.raises(NotImplementedError):
        ComplianceRecoveryService.verify_integrity(dummy_path)

    with pytest.raises(NotImplementedError):
        ComplianceRecoveryService.create_backup(dummy_path)

    with pytest.raises(NotImplementedError):
        ComplianceRecoveryService.repair_catalog(dummy_path)

    with pytest.raises(NotImplementedError):
        ComplianceRecoveryService.restore_from_backup(dummy_path)

    with pytest.raises(NotImplementedError):
        execute("recovery-verify")

    with pytest.raises(NotImplementedError):
        execute("recovery-backup")

    with pytest.raises(NotImplementedError):
        execute("recovery-repair")

    with pytest.raises(NotImplementedError):
        execute("recovery-restore")
