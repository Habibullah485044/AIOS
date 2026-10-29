"""Model Backend Adapters Recovery & Validation Subsystem (T-03255 scaffold).

Enforces MODRECV-INV1..MODRECV-INV5: record conservation, health state consistency,
path traversal immunity, PoR Invariant I-2 gating, and atomic quarantine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

MAX_CONFIG_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_PATH_LEN = 1024

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


def sanitize_error_message(msg: str) -> str:
    """Redacts absolute filesystem paths from error messages."""
    return re.sub(r"[a-zA-Z]:\\[^\s]+|/[^\s]+", "[REDACTED_PATH]", msg)


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
            "message": self.message,
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
            "store_path": self.store_path,
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
            "quarantine_path": self.quarantine_path,
            "backup_path": self.backup_path,
            "error": self.error,
            "recovered_at_utc": self.recovered_at_utc,
        }


class ModelBackendRecoveryEngine:
    """Engine for validating and recovering model backend configuration files."""

    def validate_config_file(self, path: str) -> ModelConfigValidationReport:
        """Validates configuration file on disk (pure read-only, 0 tokens)."""
        raise NotImplementedError("Scaffold only — implemented in T-03256")

    def recover_config_file(
        self, path: str, capability_token: str, create_backup: bool = True
    ) -> ModelRecoveryResult:
        """Quarantines corrupt configuration and initializes safe fallback (token-gated)."""
        raise NotImplementedError("Scaffold only — implemented in T-03256")
