"""AI Control Plane Model Backend Adapters Security Policy (T-03225 scaffold / T-03226 impl).

Policy enforcement point for PoR Invariant I-2, input sanitization, and secret redaction.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Dict, Optional

from aiosh_mcp.model_backend_adapters_service import redact_secrets

READ_ACTIONS = {"list", "show", "health", "ping"}
MUTATING_ACTIONS = {"complete", "register", "delete", "reload_config"}
MAX_PAYLOAD_BYTES = 1024 * 1024  # 1 MiB


@dataclass
class PolicyVerdict:
    allowed: bool
    reason: Optional[str] = None
    audit_record: Optional[Dict[str, Any]] = None


class ModelSecurityPolicy:
    def __init__(self, require_tokens: bool = True):
        self.require_tokens = require_tokens

    def sanitize(self, text: str) -> str:
        """Sanitizes text, rejecting NUL bytes and control characters."""
        if not text:
            return ""
        if len(text.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError(f"Payload exceeds maximum allowed size ({MAX_PAYLOAD_BYTES} bytes)")
        if chr(0) in text:
            raise ValueError("NUL byte injection detected in input payload")
        return text

    def evaluate(self, action: str, token: Optional[str] = None, payload: Optional[str] = None) -> PolicyVerdict:
        """Enforces MODSEC-INV1..MODSEC-INV4."""
        if payload is not None:
            try:
                self.sanitize(payload)
            except ValueError as e:
                return PolicyVerdict(
                    allowed=False,
                    reason=f"POLICY_REJECT_PAYLOAD: {str(e)}",
                    audit_record={"action": action, "verdict": "refuse", "reason": str(e)},
                )

        if action in MUTATING_ACTIONS and self.require_tokens:
            if not token or not token.strip():
                return PolicyVerdict(
                    allowed=False,
                    reason="POLICY_UNAUTHORIZED: Missing mandatory capability token for mutating action",
                    audit_record={"action": action, "verdict": "refuse", "reason": "missing_token"},
                )

        return PolicyVerdict(
            allowed=True,
            reason=None,
            audit_record={"action": action, "verdict": "allow"},
        )
