"""Comprehensive Unit Tests for Model Backend Adapters Recovery & Validation (T-03257)."""

import json
from pathlib import Path
import pytest
from aiosh_mcp.model_backend_adapters_recovery import (
    ModelValidationIssue,
    ModelConfigValidationReport,
    ModelRecoveryResult,
    ModelBackendRecoveryEngine,
    validate_model_store_path,
    sanitize_error_message,
    MAX_PATH_LEN,
    MODRECV_ERR_INVALID_PATH,
    MODRECV_ERR_UNAUTHORIZED,
    MODRECV_ERR_CORRUPT_JSON,
    MODRECV_ERR_SCHEMA_VIOLATION,
    MODRECV_ERR_IO,
)


class TestPathValidationAndSanitization:
    @pytest.mark.parametrize("valid_path", [
        "config/models.json",
        "models.json",
        "nested/dir/path/config.json",
        "a_b-c.1.json",
    ])
    def test_valid_paths(self, valid_path: str):
        p = validate_model_store_path(valid_path)
        assert str(p).replace("\\", "/").endswith(valid_path)

    @pytest.mark.parametrize("invalid_path", [
        "",
        "   ",
        "../models.json",
        "..\\models.json",
        "nested/../../secret.json",
        "models.json\0malicious",
        "C:\\models.json:stream",
        "CON",
        "con.json",
        "aux.txt",
        "com1",
        "lpt2",
        "a" * (MAX_PATH_LEN + 1),
    ])
    def test_invalid_paths_rejected(self, invalid_path: str):
        with pytest.raises(ValueError, match=MODRECV_ERR_INVALID_PATH):
            validate_model_store_path(invalid_path)

    def test_sanitize_error_message(self):
        msg = r"Failed to open C:\Users\Admin\secrets\models.json and /var/log/private.log"
        cleaned = sanitize_error_message(msg)
        assert r"C:\Users" not in cleaned
        assert "/var/log" not in cleaned
        assert "[REDACTED_PATH]" in cleaned


class TestValidationReportInvariants:
    def test_invariants_hold_on_valid_report(self):
        report = ModelConfigValidationReport(
            store_path="config/models.json",
            is_healthy=True,
            total_models=4,
            valid_models=4,
            invalid_models=0,
            issues=[],
        )
        report.validate_invariants()
        assert report.to_dict()["is_healthy"] is True

    def test_invariant_1_violation_raises(self):
        # total_models (5) != valid (3) + invalid (1)
        report = ModelConfigValidationReport(
            store_path="config/models.json",
            is_healthy=False,
            total_models=5,
            valid_models=3,
            invalid_models=1,
            issues=[ModelValidationIssue("error", "ERR", "msg", "m1")],
        )
        with pytest.raises(AssertionError, match="MODRECV-INV1"):
            report.validate_invariants()

    def test_invariant_2_violation_raises(self):
        # is_healthy is True despite having invalid models
        report = ModelConfigValidationReport(
            store_path="config/models.json",
            is_healthy=True,
            total_models=2,
            valid_models=1,
            invalid_models=1,
            issues=[ModelValidationIssue("error", "ERR", "msg", "m1")],
        )
        with pytest.raises(AssertionError, match="MODRECV-INV2"):
            report.validate_invariants()


class TestRecoveryEngineValidation:
    @pytest.fixture
    def engine(self):
        return ModelBackendRecoveryEngine()

    def test_validate_nonexistent_file(self, engine, tmp_path: Path):
        missing = tmp_path / "does_not_exist.json"
        report = engine.validate_config_file(str(missing))
        assert report.is_healthy is False
        assert report.total_models == 0
        assert any(i.code == "MODRECV_ERR_IO" for i in report.issues)

    def test_validate_corrupt_json_syntax(self, engine, tmp_path: Path):
        corrupt = tmp_path / "bad_syntax.json"
        corrupt.write_text("{ unquoted: [ 1, 2, ", encoding="utf-8")
        report = engine.validate_config_file(str(corrupt))
        assert report.is_healthy is False
        assert any(i.code == MODRECV_ERR_CORRUPT_JSON for i in report.issues)

    def test_validate_not_json_dict_or_list(self, engine, tmp_path: Path):
        file = tmp_path / "scalar.json"
        file.write_text('"just a string"', encoding="utf-8")
        report = engine.validate_config_file(str(file))
        assert report.is_healthy is False
        assert any(i.code == MODRECV_ERR_SCHEMA_VIOLATION for i in report.issues)

    def test_validate_missing_models_key(self, engine, tmp_path: Path):
        file = tmp_path / "no_models_key.json"
        file.write_text(json.dumps({"version": "1.0", "name": "foo"}), encoding="utf-8")
        report = engine.validate_config_file(str(file))
        assert report.is_healthy is False
        assert any("Missing required top-level 'models' array" in i.message for i in report.issues)

    def test_validate_invalid_model_entries(self, engine, tmp_path: Path):
        file = tmp_path / "invalid_entries.json"
        data = {
            "models": [
                "not_a_dict",
                {
                    "name": "bad name with spaces",
                    "provider": "openai",
                },
                {
                    "name": "valid-model",
                    "provider": "unknown_provider",
                },
                {
                    "name": "valid-model-2",
                    "provider": "mock",
                    "endpoint_url": "ftp://unsupported.com",
                },
                {
                    "name": "valid-model-3",
                    "provider": "mock",
                    "max_tokens": -50,
                },
            ]
        }
        file.write_text(json.dumps(data), encoding="utf-8")
        report = engine.validate_config_file(str(file))
        assert report.is_healthy is False
        assert report.total_models == 5
        assert report.valid_models == 0
        assert report.invalid_models == 5

    def test_validate_healthy_config(self, engine, tmp_path: Path):
        file = tmp_path / "healthy.json"
        data = {
            "models": [
                {
                    "name": "prod-gpt4",
                    "provider": "openai",
                    "endpoint_url": "https://api.openai.com/v1",
                    "max_tokens": 4096,
                },
                {
                    "name": "prod-claude",
                    "provider": "anthropic",
                    "endpoint_url": "https://api.anthropic.com/v1",
                    "max_tokens": 8192,
                },
                {
                    "name": "local-ollama",
                    "provider": "ollama",
                    "endpoint_url": "http://localhost:11434",
                    "max_tokens": 2048,
                },
            ]
        }
        file.write_text(json.dumps(data), encoding="utf-8")
        report = engine.validate_config_file(str(file))
        assert report.is_healthy is True
        assert report.total_models == 3
        assert report.valid_models == 3
        assert report.invalid_models == 0
        assert len(report.issues) == 0


class TestRecoveryEngineExecution:
    @pytest.fixture
    def engine(self):
        return ModelBackendRecoveryEngine()

    def test_token_gating(self, engine, tmp_path: Path):
        file = tmp_path / "target.json"
        with pytest.raises(ValueError, match=MODRECV_ERR_UNAUTHORIZED):
            engine.recover_config_file(str(file), capability_token="")

    def test_recovery_on_corrupt_file(self, engine, tmp_path: Path):
        target = tmp_path / "defective.json"
        target.write_text("TRUNCATED_JSON_CHUNK_{{{", encoding="utf-8")

        result = engine.recover_config_file(
            str(target), capability_token="cap_test_token_valid", create_backup=True
        )
        assert result.ok is True
        assert result.action_taken == "QUARANTINE_AND_RESTORE_DEFAULT"
        assert result.quarantine_path is not None
        assert Path(result.quarantine_path).exists()
        assert result.backup_path is not None
        assert Path(result.backup_path).exists()

        # Target file was written with default fallback configuration
        assert target.exists()
        content = json.loads(target.read_text(encoding="utf-8"))
        assert content["default_fallback"] == "mock-fallback"
        assert len(content["models"]) == 1

        # Restored config passes validation
        report = engine.validate_config_file(str(target))
        assert report.is_healthy is True

    def test_recovery_without_backup(self, engine, tmp_path: Path):
        target = tmp_path / "defective_no_bak.json"
        target.write_text("BROKEN", encoding="utf-8")

        result = engine.recover_config_file(
            str(target), capability_token="cap_test_token_valid", create_backup=False
        )
        assert result.ok is True
        assert result.backup_path is None
        assert result.quarantine_path is not None
        assert Path(result.quarantine_path).exists()
