"""Tests for Model Backend Adapters Recovery & Validation Implementation (T-03256)."""

import json
from pathlib import Path
import pytest
from aiosh_mcp.model_backend_adapters_recovery import (
    ModelBackendRecoveryEngine,
    MODRECV_ERR_UNAUTHORIZED,
    MODRECV_ERR_CORRUPT_JSON,
    MODRECV_ERR_SCHEMA_VIOLATION,
)


def test_validate_valid_config(tmp_path: Path):
    cfg_file = tmp_path / "valid_models.json"
    cfg_data = {
        "models": [
            {
                "name": "gpt-4o",
                "provider": "openai",
                "endpoint_url": "https://api.openai.com/v1",
                "max_tokens": 4096,
            },
            {
                "name": "claude-3-5-sonnet",
                "provider": "anthropic",
                "endpoint_url": "https://api.anthropic.com/v1",
                "max_tokens": 8192,
            },
        ]
    }
    cfg_file.write_text(json.dumps(cfg_data), encoding="utf-8")

    engine = ModelBackendRecoveryEngine()
    report = engine.validate_config_file(str(cfg_file))
    assert report.is_healthy is True
    assert report.total_models == 2
    assert report.valid_models == 2
    assert report.invalid_models == 0
    assert len(report.issues) == 0


def test_validate_corrupt_json(tmp_path: Path):
    cfg_file = tmp_path / "corrupt_syntax.json"
    cfg_file.write_text("{ models: [ broken json content ...", encoding="utf-8")

    engine = ModelBackendRecoveryEngine()
    report = engine.validate_config_file(str(cfg_file))
    assert report.is_healthy is False
    assert any(i.code == MODRECV_ERR_CORRUPT_JSON for i in report.issues)


def test_validate_schema_violations(tmp_path: Path):
    cfg_file = tmp_path / "schema_err.json"
    cfg_data = {
        "models": [
            {
                "name": "unsupported-model",
                "provider": "unsupported_unknown_vendor",
                "max_tokens": 1000,
            },
            {
                "name": "",  # Empty name
                "provider": "openai",
            },
        ]
    }
    cfg_file.write_text(json.dumps(cfg_data), encoding="utf-8")

    engine = ModelBackendRecoveryEngine()
    report = engine.validate_config_file(str(cfg_file))
    assert report.is_healthy is False
    assert report.invalid_models == 2
    assert report.valid_models == 0
    assert report.total_models == 2


def test_recovery_token_gate_violation(tmp_path: Path):
    cfg_file = tmp_path / "target.json"
    engine = ModelBackendRecoveryEngine()

    with pytest.raises(ValueError, match=MODRECV_ERR_UNAUTHORIZED):
        engine.recover_config_file(str(cfg_file), capability_token="")

    with pytest.raises(ValueError, match=MODRECV_ERR_UNAUTHORIZED):
        engine.recover_config_file(str(cfg_file), capability_token="   ")


def test_recovery_workflow_quarantine_and_restore(tmp_path: Path):
    cfg_file = tmp_path / "models_to_recover.json"
    cfg_file.write_text("CORRUPTED_CONFIG_PAYLOAD", encoding="utf-8")

    engine = ModelBackendRecoveryEngine()
    res = engine.recover_config_file(
        str(cfg_file), capability_token="cap_valid_token_12345", create_backup=True
    )
    assert res.ok is True
    assert res.action_taken == "QUARANTINE_AND_RESTORE_DEFAULT"
    assert res.quarantine_path is not None
    assert Path(res.quarantine_path).exists()
    assert Path(res.backup_path).exists()

    # Verify the target file was restored to valid default config
    assert cfg_file.exists()
    restored_report = engine.validate_config_file(str(cfg_file))
    assert restored_report.is_healthy is True
    assert restored_report.valid_models >= 1
