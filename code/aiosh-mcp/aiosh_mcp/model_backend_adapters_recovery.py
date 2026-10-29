"""Model Backend Adapters Recovery & Validation Subsystem (T-03260 hardened).

Enforces MODRECV-INV1..MODRECV-INV5: record conservation, health state consistency,
path traversal immunity, PoR Invariant I-2 gating, atomic quarantine, and leak-free error paths.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import shutil
from typing import Any, Dict, List, Optional

logger = logging.getLogger("aiosh_mcp.model_backend_adapters_recovery")

MAX_CONFIG_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_PATH_LEN = 1024
MAX_CONFIG_MODELS_CAP = 128

MODRECV_ERR_INVALID_PATH = "MODRECV_ERR_INVALID_PATH"
MODRECV_ERR_CORRUPT_JSON = "MODRECV_ERR_CORRUPT_JSON"
MODRECV_ERR_SCHEMA_VIOLATION = "MODRECV_ERR_SCHEMA_VIOLATION"
MODRECV_ERR_UNAUTHORIZED = "MODRECV_ERR_UNAUTHORIZED"
MODRECV_ERR_IO = "MODRECV_ERR_IO"
MODRECV_ERR_INTERNAL = "MODRECV_ERR_INTERNAL"

RESERVED_DEVICE_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

VALID_PROVIDERS = {"openai", "anthropic", "ollama", "mock", "gemini", "azure"}
MODEL_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")
SECRET_PATTERN = re.compile(r"(sk-[a-zA-Z0-9_\-]{20,}|ghp_[a-zA-Z0-9_\-]{20,}|Bearer\s+[a-zA-Z0-9_\-\.]{20,})", re.IGNORECASE)


def mask_secrets(text: str) -> str:
    """Masks API keys, tokens, and authorization credentials in text."""
    if not text:
        return ""
    return SECRET_PATTERN.sub("[REDACTED_SECRET]", text)


def sanitize_error_message(msg: str) -> str:
    """Redacts absolute filesystem paths and secrets from error messages."""
    redacted = re.sub(r"[a-zA-Z]:\\[^\s]+|/[^\s]+", "[REDACTED_PATH]", msg)
    return mask_secrets(redacted)


def validate_model_store_path(path: str) -> Path:
    """Validates target config path against path traversal, NUL bytes, length bounds, and reserved device names."""
    if not path or not path.strip():
        raise ValueError(f"{MODRECV_ERR_INVALID_PATH}: empty config path")
    trimmed = path.strip()
    if len(trimmed) > MAX_PATH_LEN:
        raise ValueError(f"{MODRECV_ERR_INVALID_PATH}: path exceeds {MAX_PATH_LEN} characters")
    if "\0" in trimmed:
        raise ValueError(f"{MODRECV_ERR_INVALID_PATH}: NUL byte detected in path")
    p = Path(trimmed)
    parts = p.parts
    if ".." in parts:
        raise ValueError(f"{MODRECV_ERR_INVALID_PATH}: directory traversal sequence detected")
    for part in parts:
        stem = Path(part).stem.upper()
        if stem in RESERVED_DEVICE_NAMES:
            raise ValueError(f"{MODRECV_ERR_INVALID_PATH}: reserved device name detected: {part}")
    rest = trimmed[2:] if (len(trimmed) >= 2 and trimmed[1] == ":" and trimmed[0].isalpha()) else trimmed
    if ":" in rest:
        raise ValueError(f"{MODRECV_ERR_INVALID_PATH}: alternate data stream detected in path")
    return p


@dataclass(frozen=True)
class ModelValidationIssue:
    severity: str    # "error" | "warning"
    code: str
    message: str
    model_name: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": mask_secrets(self.message),
            "model_name": self.model_name,
        }


@dataclass
class ModelConfigValidationReport:
    store_path: str
    is_healthy: bool
    total_models: int
    valid_models: int
    invalid_models: int
    issues: List[ModelValidationIssue] = field(default_factory=list)
    validated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def validate_invariants(self) -> None:
        """Enforces MODRECV-INV1 and MODRECV-INV2."""
        if self.total_models != (self.valid_models + self.invalid_models):
            raise AssertionError(
                f"MODRECV-INV1 violated: total_models ({self.total_models}) != "
                f"valid ({self.valid_models}) + invalid ({self.invalid_models})"
            )
        expected_healthy = (len(self.issues) == 0 and self.invalid_models == 0)
        if self.is_healthy != expected_healthy:
            raise AssertionError(
                f"MODRECV-INV2 violated: is_healthy ({self.is_healthy}) != {expected_healthy}"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "store_path": sanitize_error_message(self.store_path),
            "is_healthy": self.is_healthy,
            "total_models": self.total_models,
            "valid_models": self.valid_models,
            "invalid_models": self.invalid_models,
            "issues": [i.to_dict() for i in self.issues],
            "validated_at_utc": self.validated_at_utc,
        }


@dataclass
class ModelRecoveryResult:
    ok: bool
    action_taken: str
    quarantine_path: Optional[str]
    backup_path: Optional[str]
    error: Optional[str] = None
    recovered_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "action_taken": self.action_taken,
            "quarantine_path": sanitize_error_message(self.quarantine_path) if self.quarantine_path else None,
            "backup_path": sanitize_error_message(self.backup_path) if self.backup_path else None,
            "error": sanitize_error_message(self.error) if self.error else None,
            "recovered_at_utc": self.recovered_at_utc,
        }


class ModelBackendRecoveryEngine:
    """Engine for validating and recovering model backend configuration files."""

    def validate_config_file(self, path: str) -> ModelConfigValidationReport:
        """Validates configuration file on disk (pure read-only, 0 tokens)."""
        target_path = validate_model_store_path(path)
        issues: List[ModelValidationIssue] = []

        if not target_path.exists() or not target_path.is_file():
            issues.append(
                ModelValidationIssue(
                    severity="error",
                    code="MODRECV_ERR_IO",
                    message="Configuration file does not exist or is not a file",
                    model_name="_global_",
                )
            )
            report = ModelConfigValidationReport(
                store_path=str(target_path),
                is_healthy=False,
                total_models=0,
                valid_models=0,
                invalid_models=0,
                issues=issues,
            )
            report.validate_invariants()
            return report

        try:
            stat = target_path.stat()
            if stat.st_size > MAX_CONFIG_FILE_BYTES:
                issues.append(
                    ModelValidationIssue(
                        severity="error",
                        code="MODRECV_ERR_SCHEMA_VIOLATION",
                        message=f"File exceeds maximum allowed size of {MAX_CONFIG_FILE_BYTES} bytes",
                        model_name="_global_",
                    )
                )
                report = ModelConfigValidationReport(
                    store_path=str(target_path),
                    is_healthy=False,
                    total_models=0,
                    valid_models=0,
                    invalid_models=0,
                    issues=issues,
                )
                report.validate_invariants()
                return report

            with open(target_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception as e:
            issues.append(
                ModelValidationIssue(
                    severity="error",
                    code="MODRECV_ERR_IO",
                    message=f"Failed to read file: {e}",
                    model_name="_global_",
                )
            )
            report = ModelConfigValidationReport(
                store_path=str(target_path),
                is_healthy=False,
                total_models=0,
                valid_models=0,
                invalid_models=0,
                issues=issues,
            )
            report.validate_invariants()
            return report

        try:
            parsed = json.loads(content)
        except Exception as e:
            issues.append(
                ModelValidationIssue(
                    severity="error",
                    code="MODRECV_ERR_CORRUPT_JSON",
                    message=f"Invalid JSON syntax: {e}",
                    model_name="_global_",
                )
            )
            report = ModelConfigValidationReport(
                store_path=str(target_path),
                is_healthy=False,
                total_models=0,
                valid_models=0,
                invalid_models=0,
                issues=issues,
            )
            report.validate_invariants()
            return report

        # Extract model definitions
        raw_models: List[Any] = []
        if isinstance(parsed, dict):
            if "models" in parsed:
                if isinstance(parsed["models"], list):
                    raw_models = parsed["models"]
                else:
                    issues.append(
                        ModelValidationIssue(
                            severity="error",
                            code="MODRECV_ERR_SCHEMA_VIOLATION",
                            message="'models' field must be a list",
                            model_name="_global_",
                        )
                    )
            else:
                issues.append(
                    ModelValidationIssue(
                        severity="error",
                        code="MODRECV_ERR_SCHEMA_VIOLATION",
                        message="Missing required top-level 'models' array",
                        model_name="_global_",
                    )
                )
        elif isinstance(parsed, list):
            raw_models = parsed
        else:
            issues.append(
                ModelValidationIssue(
                    severity="error",
                    code="MODRECV_ERR_SCHEMA_VIOLATION",
                    message="Configuration must be a JSON object or list",
                    model_name="_global_",
                )
            )

        if len(raw_models) > MAX_CONFIG_MODELS_CAP:
            issues.append(
                ModelValidationIssue(
                    severity="error",
                    code="MODRECV_ERR_SCHEMA_VIOLATION",
                    message=f"Model count {len(raw_models)} exceeds maximum allowed limit of {MAX_CONFIG_MODELS_CAP}",
                    model_name="_global_",
                )
            )

        valid_count = 0
        invalid_count = 0

        for idx, item in enumerate(raw_models):
            model_name = f"model_{idx}"
            model_has_error = False

            if not isinstance(item, dict):
                issues.append(
                    ModelValidationIssue(
                        severity="error",
                        code="MODRECV_ERR_SCHEMA_VIOLATION",
                        message="Model entry must be a JSON object",
                        model_name=model_name,
                    )
                )
                invalid_count += 1
                continue

            name = item.get("name")
            if not isinstance(name, str) or not name.strip() or not MODEL_NAME_PATTERN.match(name.strip()):
                issues.append(
                    ModelValidationIssue(
                        severity="error",
                        code="MODRECV_ERR_SCHEMA_VIOLATION",
                        message="Model name missing, empty, or does not match identifier syntax",
                        model_name=str(name or model_name),
                    )
                )
                model_has_error = True
            else:
                model_name = name.strip()

            provider = item.get("provider")
            if not isinstance(provider, str) or provider.lower() not in VALID_PROVIDERS:
                issues.append(
                    ModelValidationIssue(
                        severity="error",
                        code="MODRECV_ERR_SCHEMA_VIOLATION",
                        message=f"Invalid or unsupported provider: {provider}",
                        model_name=model_name,
                    )
                )
                model_has_error = True

            endpoint_url = item.get("endpoint_url")
            if endpoint_url is not None:
                if not isinstance(endpoint_url, str) or not (
                    endpoint_url.startswith("http://") or endpoint_url.startswith("https://")
                ):
                    issues.append(
                        ModelValidationIssue(
                            severity="error",
                            code="MODRECV_ERR_SCHEMA_VIOLATION",
                            message="endpoint_url must start with http:// or https://",
                            model_name=model_name,
                        )
                    )
                    model_has_error = True

            max_tokens = item.get("max_tokens")
            if max_tokens is not None:
                if not isinstance(max_tokens, int) or max_tokens < 1:
                    issues.append(
                        ModelValidationIssue(
                            severity="error",
                            code="MODRECV_ERR_SCHEMA_VIOLATION",
                            message="max_tokens must be an integer >= 1",
                            model_name=model_name,
                        )
                    )
                    model_has_error = True

            if model_has_error:
                invalid_count += 1
            else:
                valid_count += 1

        total_models = valid_count + invalid_count
        is_healthy = (len(issues) == 0 and invalid_count == 0)

        report = ModelConfigValidationReport(
            store_path=str(target_path),
            is_healthy=is_healthy,
            total_models=total_models,
            valid_models=valid_count,
            invalid_models=invalid_count,
            issues=issues,
        )
        report.validate_invariants()
        return report

    def recover_config_file(
        self, path: str, capability_token: str, create_backup: bool = True
    ) -> ModelRecoveryResult:
        """Quarantines corrupt configuration and initializes safe fallback (token-gated)."""
        # PoR Invariant I-2: state-changing recovery strictly requires capability token
        if not capability_token or not capability_token.strip():
            raise ValueError(f"{MODRECV_ERR_UNAUTHORIZED}: capability token required for recovery")

        target_path = validate_model_store_path(path)
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        quarantine_path: Optional[str] = None
        backup_path: Optional[str] = None
        temp_path: Optional[Path] = None

        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)

            if target_path.exists():
                if create_backup:
                    b_path = target_path.with_name(f"{target_path.name}.bak.{timestamp_str}")
                    shutil.copy2(target_path, b_path)
                    backup_path = str(b_path)

                q_path = target_path.with_name(f"{target_path.name}.corrupt.{timestamp_str}")
                shutil.move(target_path, q_path)
                quarantine_path = str(q_path)

            default_config = {
                "schema_version": "1.0",
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "default_fallback": "mock-fallback",
                "models": [
                    {
                        "name": "mock-fallback",
                        "provider": "mock",
                        "endpoint_url": "http://localhost:8080/mock",
                        "max_tokens": 4096,
                        "timeout_ms": 5000,
                    }
                ],
            }

            temp_path = target_path.with_name(f"{target_path.name}.tmp.{os.getpid()}")
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(default_config, f, indent=2)
            os.replace(temp_path, target_path)

            logger.info(
                f"AUDIT: Model config recovery succeeded: target={sanitize_error_message(str(target_path))} "
                f"quarantine={sanitize_error_message(quarantine_path or '')}"
            )

            return ModelRecoveryResult(
                ok=True,
                action_taken="QUARANTINE_AND_RESTORE_DEFAULT",
                quarantine_path=quarantine_path,
                backup_path=backup_path,
            )
        except Exception as e:
            logger.error(
                f"AUDIT: Model config recovery failed: target={sanitize_error_message(str(target_path))} error={e}"
            )
            return ModelRecoveryResult(
                ok=False,
                action_taken="RECOVERY_FAILED",
                quarantine_path=quarantine_path,
                backup_path=backup_path,
                error=sanitize_error_message(str(e)),
            )
        finally:
            if temp_path and temp_path.exists():
                try:
                    temp_path.unlink(missing_ok=True)
                except Exception:
                    pass


_GLOBAL_RECOVERY_ENGINE = ModelBackendRecoveryEngine()


def get_global_recovery_engine() -> ModelBackendRecoveryEngine:
    """Returns the process-wide ModelBackendRecoveryEngine singleton."""
    return _GLOBAL_RECOVERY_ENGINE


def register_model_recovery_tools(mcp_server: Any) -> None:
    """Registers Model Backend Adapters Recovery & Validation MCP tools (T-03258 / T-03260)."""

    @mcp_server.tool()
    def aios_model_validate_config(config_path: str) -> dict:
        """Validates model backend configuration file (pure read-only, 0 tokens)."""
        try:
            report = get_global_recovery_engine().validate_config_file(config_path)
            return {
                "status": "success",
                "ok": True,
                "data": report.to_dict(),
            }
        except ValueError as ve:
            return {
                "status": "error",
                "ok": False,
                "error": MODRECV_ERR_INVALID_PATH,
                "message": sanitize_error_message(str(ve)),
            }
        except Exception as e:
            logger.error(f"Unexpected error validating model config: {e}")
            return {
                "status": "error",
                "ok": False,
                "error": MODRECV_ERR_INTERNAL,
                "message": sanitize_error_message(str(e)),
            }

    @mcp_server.tool()
    def aios_model_recover_config(
        config_path: str, capability_token: str, create_backup: bool = True
    ) -> dict:
        """Quarantines corrupt model config and restores safe fallback (token-gated, Invariant I-2)."""
        try:
            result = get_global_recovery_engine().recover_config_file(
                path=config_path, capability_token=capability_token, create_backup=create_backup
            )
            return {
                "status": "success" if result.ok else "error",
                "ok": result.ok,
                "data": result.to_dict(),
            }
        except ValueError as ve:
            err_code = MODRECV_ERR_UNAUTHORIZED if "capability token" in str(ve) else MODRECV_ERR_INVALID_PATH
            return {
                "status": "error",
                "ok": False,
                "error": err_code,
                "message": sanitize_error_message(str(ve)),
            }
        except Exception as e:
            logger.error(f"Unexpected error recovering model config: {e}")
            return {
                "status": "error",
                "ok": False,
                "error": MODRECV_ERR_INTERNAL,
                "message": sanitize_error_message(str(e)),
            }
