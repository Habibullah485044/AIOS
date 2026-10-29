"""Hardening tests for Model Backend Adapters Recovery & Validation (T-03260)."""

import json
from pathlib import Path
import pytest
from aiosh_mcp.model_backend_adapters_recovery import (
    ModelBackendRecoveryEngine,
    mask_secrets,
    sanitize_error_message,
    MAX_CONFIG_MODELS_CAP,
    MODRECV_ERR_SCHEMA_VIOLATION,
)


def test_mask_secrets():
    raw = "Failed using key: sk-ant-api03-abcdef1234567890abcdef1234567890"
    masked = mask_secrets(raw)
    assert "[REDACTED_SECRET]" in masked
    assert "sk-ant" not in masked


def test_sanitize_error_message_path_and_secret():
    raw = r"Error opening C:\secret\models.json with key sk-openai12345678901234567890"
    sanitized = sanitize_error_message(raw)
    assert r"C:\secret" not in sanitized
    assert "[REDACTED_PATH]" in sanitized
    assert "[REDACTED_SECRET]" in sanitized


def test_model_count_cap_exceeded(tmp_path: Path):
    engine = ModelBackendRecoveryEngine()
    cfg_file = tmp_path / "excessive_models.json"
    models = [
        {
            "name": f"model-{i}",
            "provider": "mock",
        }
        for i in range(MAX_CONFIG_MODELS_CAP + 10)
    ]
    cfg_file.write_text(json.dumps({"models": models}), encoding="utf-8")

    report = engine.validate_config_file(str(cfg_file))
    assert report.is_healthy is False
    assert any(
        i.code == MODRECV_ERR_SCHEMA_VIOLATION and "exceeds maximum allowed limit" in i.message
        for i in report.issues
    )


def test_recovery_temp_file_cleanup_on_success(tmp_path: Path):
    engine = ModelBackendRecoveryEngine()
    target = tmp_path / "cleanup_test.json"
    target.write_text("INITIAL", encoding="utf-8")

    result = engine.recover_config_file(
        str(target), capability_token="cap_cleanup_test_token"
    )
    assert result.ok is True
    # Ensure no lingering .tmp files exist in tmp_path
    tmp_files = list(tmp_path.glob("*.tmp.*"))
    assert len(tmp_files) == 0
