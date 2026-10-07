"""Proof of Restraint — Standalone Proof Verifier (Component 5).

Sprint / Architecture: ADR-0037, PLAN.md §Layer 2, Invariant I-4.
Zero-trust mathematical and cryptographic verifier for RestraintProofPackage.
Requires ZERO access to audit.db, agent host, or network services.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    proof_id: str
    reason: Optional[str] = None
    checks: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "proof_id": self.proof_id,
            "reason": self.reason,
            "checks": self.checks,
        }

    def to_canonical_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


def verify_restraint_proof(
    proof: Union[dict[str, Any], str, Path],
    trusted_pubkeys: Union[list[str], set[str], str],
) -> VerificationResult:
    """Verifies self-contained RestraintProofPackage purely mathematically against trusted Ed25519 public keys.

    Zero database dependencies.
    """
    raise NotImplementedError("T-02874 SCAFFOLD: verify_restraint_proof body implemented in T-02875")
