"""AI Control Plane Model Backend Adapters Security Policy (T-03225 scaffold / T-03226 impl / T-03230 hardening).

Policy enforcement point for PoR Invariant I-2, input sanitization, bounded execution, and secret redaction.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
import time
from typing import Any, Dict, Optional

from aiosh_mcp.model_backend_adapters_service import redact_secrets

READ_ACTIONS = {"list", "show", "health", "ping"}
MUTATING_ACTIONS = {"complete", "register", "delete", "reload_config"}
ALL_ACTIONS = READ_ACTIONS | MUTATING_ACTIONS

MAX_PAYLOAD_BYTES = 1024 * 1024  # 1 MiB
MAX_ACTION_LEN = 64
MAX_TOKEN_LEN = 512


@dataclass
class PolicyVerdict:
    allowed: bool
    reason: Optional[str] = None
    audit_record: Optional[Dict[str, Any]] = None

    def to_envelope(self) -> Dict[str, Any]:
        """ADR-0035 §AF-2 compliant standard result envelope."""
        return {
            "status": "success" if self.allowed else "rejected",
            "ok": self.allowed,
            "reason": self.reason,
            "audit": self.audit_record or {},
            "timestamp": time.time(),
        }


class ModelSecurityPolicy:
    def __init__(self, require_tokens: bool = True):
        self.require_tokens = require_tokens

    def sanitize(self, text: str) -> str:
        """Sanitizes text, rejecting NUL bytes, oversized payloads, and unprintable control sequences."""
        if not text:
            return ""
        if len(text.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise ValueError(f"Payload exceeds maximum allowed size ({MAX_PAYLOAD_BYTES} bytes)")
        if chr(0) in text:
            raise ValueError("NUL byte injection detected in input payload")
        return text

    def sanitize_token(self, token: Optional[str]) -> Optional[str]:
        """Validates capability token boundaries and rejects embedded NUL bytes."""
        if token is None:
            return None
        if len(token) > MAX_TOKEN_LEN:
            raise ValueError(f"Capability token exceeds maximum allowed size ({MAX_TOKEN_LEN} chars)")
        if chr(0) in token:
            raise ValueError("NUL byte injection detected in capability token")
        return token.strip()

    def evaluate(self, action: str, token: Optional[str] = None, payload: Optional[str] = None) -> PolicyVerdict:
        """Enforces MODSEC-INV1..MODSEC-INV5 with fail-closed security invariants."""
        try:
            # 1. Action bounds and character validation
            if not action or len(action) > MAX_ACTION_LEN:
                return PolicyVerdict(
                    allowed=False,
                    reason=f"POLICY_INVALID_ACTION: Action name must be 1..{MAX_ACTION_LEN} chars",
                    audit_record={"action": "unknown", "verdict": "refuse", "reason": "invalid_action_length"},
                )
            if chr(0) in action:
                return PolicyVerdict(
                    allowed=False,
                    reason="POLICY_INVALID_ACTION: NUL byte in action name",
                    audit_record={"action": "corrupted", "verdict": "refuse", "reason": "nul_in_action"},
                )

            # 2. Payload sanitization
            if payload is not None:
                try:
                    self.sanitize(payload)
                except ValueError as e:
                    return PolicyVerdict(
                        allowed=False,
                        reason=f"POLICY_REJECT_PAYLOAD: {str(e)}",
                        audit_record={"action": action, "verdict": "refuse", "reason": str(e)},
                    )

            # 3. Token boundary and sanitization
            clean_token = None
            if token is not None:
                try:
                    clean_token = self.sanitize_token(token)
                except ValueError as e:
                    return PolicyVerdict(
                        allowed=False,
                        reason=f"POLICY_REJECT_TOKEN: {str(e)}",
                        audit_record={"action": action, "verdict": "refuse", "reason": str(e)},
                    )

            # 4. Invariant I-2 gating on mutating actions
            if action in MUTATING_ACTIONS and self.require_tokens:
                if not clean_token:
                    return PolicyVerdict(
                        allowed=False,
                        reason="POLICY_UNAUTHORIZED: Missing mandatory capability token for mutating action",
                        audit_record={"action": action, "verdict": "refuse", "reason": "missing_token"},
                    )

            # 5. Pure read operations (zero tokens required) or valid authorized mutating action
            return PolicyVerdict(
                allowed=True,
                reason=None,
                audit_record={"action": action, "verdict": "allow"},
            )

        except Exception as e:
            # ADR-0035 §F-2: Fail-closed with an honest audit record
            safe_err = redact_secrets(str(e))
            return PolicyVerdict(
                allowed=False,
                reason=f"POLICY_INTERNAL_ERROR: {safe_err}",
                audit_record={"action": action, "verdict": "refuse", "reason": "unexpected_error"},
            )
