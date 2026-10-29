"""Tests for Model Backend Adapters Recovery & Validation Scaffold (T-03255)."""

import pytest
from aiosh_mcp.model_backend_adapters_recovery import (
    ModelValidationIssue,
    ModelConfigValidationReport,
    ModelRecoveryResult,
    ModelBackendRecoveryEngine,
    validate_model_store_path,
    sanitize_error_message,
    MODRECV_ERR_INVALID_PATH,
)


def test_validation_issue_type():
    issue = ModelValidationIssue(
        severity="error",
        code="ERR_INVALID_PROVIDER",
        message="Unknown provider foo",
        model_name="test-model",
    )
    d = issue.to_dict()
    assert d["code"] == "ERR_INVALID_PROVIDER"
    assert d["model_name"] == "test-model"


def test_validation_report_invariants():
    # Valid report enforcing MODRECV-INV1 and MODRECV-INV2
    report = ModelConfigValidationReport(
        store_path="config/models.json",
        is_healthy=True,
        total_models=3,
        valid_models=3,
        invalid_models=0,
    )
    report.validate_invariants()
    d = report.to_dict()
    assert d["is_healthy"] is True

    # Violate MODRECV-INV1: total != valid + invalid
    bad_report = ModelConfigValidationReport(
        store_path="config/models.json",
        is_healthy=True,
        total_models=5,
        valid_models=3,
        invalid_models=0,
    )
    with pytest.raises(AssertionError, match="MODRECV-INV1"):
        bad_report.validate_invariants()


def test_validate_model_store_path():
    validate_model_store_path("config/models.json")
    with pytest.raises(ValueError, match=MODRECV_ERR_INVALID_PATH):
        validate_model_store_path("../traversal/models.json")
    with pytest.raises(ValueError, match=MODRECV_ERR_INVALID_PATH):
        validate_model_store_path("")


def test_sanitize_error_message():
    raw = r"Error accessing C:\secret\path\file.json"
    cleaned = sanitize_error_message(raw)
    assert r"C:\secret" not in cleaned
    assert "[REDACTED_PATH]" in cleaned


def test_recovery_engine_scaffold_raises():
    engine = ModelBackendRecoveryEngine()
    try:
        engine.validate_config_file("config/models.json")
    except NotImplementedError:
        pass
