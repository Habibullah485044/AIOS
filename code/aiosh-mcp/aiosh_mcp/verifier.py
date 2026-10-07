"""Proof of Restraint — Standalone Proof Verifier (Component 5).

Sprint / Architecture: ADR-0037, PLAN.md §Layer 2, Invariant I-4.
Zero-trust mathematical and cryptographic verifier for RestraintProofPackage.
Requires ZERO access to audit.db, agent host, or network services.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

from . import anchors as anchors_mod
from . import retention as retention_mod


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


def _load_proof_dict(proof: Union[dict[str, Any], str, Path]) -> dict[str, Any]:
    if isinstance(proof, dict):
        return proof
    if isinstance(proof, (str, Path)):
        p = Path(proof)
        if p.is_file():
            content = p.read_text(encoding="utf-8")
            return json.loads(content)
        # If string is raw JSON
        if isinstance(proof, str) and (proof.startswith("{") or proof.startswith("[")):
            return json.loads(proof)
    raise ValueError(f"PARAM_INVALID: cannot parse proof from {type(proof)}")


def verify_restraint_proof(
    proof: Union[dict[str, Any], str, Path],
    trusted_pubkeys: Union[list[str], set[str], str],
) -> VerificationResult:
    """Verifies self-contained RestraintProofPackage purely mathematically against trusted Ed25519 public keys.

    Zero database dependencies.
    """
    if isinstance(trusted_pubkeys, str):
        trusted_set = {trusted_pubkeys.strip()}
    else:
        trusted_set = {k.strip() for k in trusted_pubkeys if isinstance(k, str) and k.strip()}

    checks: dict[str, bool] = {
        "schema": False,
        "grant": False,
        "anchor_keys": False,
        "anchor_sigs": False,
        "anchor_bounds": False,
        "bloom_exclusion": False,
        "live_chain": False,
    }

    # 1. CHECK_SCHEMA
    try:
        data = _load_proof_dict(proof)
    except Exception as exc:
        return VerificationResult(valid=False, proof_id="unknown", reason=f"VERIFY_FAILED: INVALID_SCHEMA: {exc}", checks=checks)

    if not isinstance(data, dict):
        return VerificationResult(valid=False, proof_id="unknown", reason="VERIFY_FAILED: INVALID_SCHEMA: proof must be a JSON object", checks=checks)

    proof_id = str(data.get("proof_id", "unknown"))
    if data.get("schema_version") != 1:
        return VerificationResult(valid=False, proof_id=proof_id, reason=f"VERIFY_FAILED: UNSUPPORTED_SCHEMA_VERSION ({data.get('schema_version')})", checks=checks)

    required_keys = ["proof_id", "grant", "window", "anchors", "segments_checked", "live_range"]
    for k in required_keys:
        if k not in data or data[k] is None:
            return VerificationResult(valid=False, proof_id=proof_id, reason=f"VERIFY_FAILED: MISSING_FIELD: {k}", checks=checks)
    checks["schema"] = True

    # 2. CHECK_GRANT
    grant = data["grant"]
    window = data["window"]
    grant_id = grant.get("grant_id")
    if not grant_id:
        return VerificationResult(valid=False, proof_id=proof_id, reason="VERIFY_FAILED: GRANT_INVALID: missing grant_id", checks=checks)

    if grant.get("redeemed_at") is not None:
        return VerificationResult(valid=False, proof_id=proof_id, reason=f"VERIFY_FAILED: GRANT_REDEEMED: grant was redeemed at {grant.get('redeemed_at')}", checks=checks)

    if not grant.get("single_use", False):
        return VerificationResult(valid=False, proof_id=proof_id, reason="VERIFY_FAILED: GRANT_INVALID: proof requires single_use=true capability grant", checks=checks)

    w_start = window.get("start")
    w_end = window.get("end")
    if not w_start or not w_end or w_start > w_end:
        return VerificationResult(valid=False, proof_id=proof_id, reason=f"VERIFY_FAILED: WINDOW_INVALID: [{w_start}, {w_end}]", checks=checks)

    # Confirm grant validity bounds claimed window
    g_issued = grant.get("issued_at")
    g_expires = grant.get("expires_at")
    if g_issued and g_issued > w_start:
        return VerificationResult(valid=False, proof_id=proof_id, reason=f"VERIFY_FAILED: GRANT_INVALID: grant issued ({g_issued}) after window start ({w_start})", checks=checks)
    if g_expires and g_expires < w_end:
        return VerificationResult(valid=False, proof_id=proof_id, reason=f"VERIFY_FAILED: GRANT_INVALID: grant expired ({g_expires}) before window end ({w_end})", checks=checks)

    checks["grant"] = True

    # 3. CHECK_ANCHOR_KEYS
    anchors = data["anchors"]
    start_anchor_dict = anchors.get("start_anchor")
    end_anchor_dict = anchors.get("end_anchor")
    if not start_anchor_dict or not end_anchor_dict:
        return VerificationResult(valid=False, proof_id=proof_id, reason="VERIFY_FAILED: MISSING_ANCHORS", checks=checks)

    sa_pub = start_anchor_dict.get("pubkey")
    ea_pub = end_anchor_dict.get("pubkey")
    if not sa_pub or sa_pub not in trusted_set:
        return VerificationResult(valid=False, proof_id=proof_id, reason=f"VERIFY_FAILED: UNTRUSTED_KEY: start_anchor pubkey {sa_pub} not trusted", checks=checks)
    if not ea_pub or ea_pub not in trusted_set:
        return VerificationResult(valid=False, proof_id=proof_id, reason=f"VERIFY_FAILED: UNTRUSTED_KEY: end_anchor pubkey {ea_pub} not trusted", checks=checks)

    checks["anchor_keys"] = True

    # 4. CHECK_ANCHOR_SIGS
    try:
        rec_start = anchors_mod.AnchorRecord(
            schema_version=start_anchor_dict["schema_version"],
            seq=start_anchor_dict["seq"],
            head_hash=start_anchor_dict["head_hash"],
            timestamp=start_anchor_dict["timestamp"],
            pubkey=start_anchor_dict["pubkey"],
            signature=start_anchor_dict["signature"],
        )
        rec_end = anchors_mod.AnchorRecord(
            schema_version=end_anchor_dict["schema_version"],
            seq=end_anchor_dict["seq"],
            head_hash=end_anchor_dict["head_hash"],
            timestamp=end_anchor_dict["timestamp"],
            pubkey=end_anchor_dict["pubkey"],
            signature=end_anchor_dict["signature"],
        )
    except KeyError as exc:
        return VerificationResult(valid=False, proof_id=proof_id, reason=f"VERIFY_FAILED: INVALID_ANCHOR_PAYLOAD: missing {exc}", checks=checks)

    if not anchors_mod.verify_checkpoint(rec_start):
        return VerificationResult(valid=False, proof_id=proof_id, reason="VERIFY_FAILED: INVALID_ANCHOR_SIGNATURE: start_anchor signature invalid", checks=checks)
    if not anchors_mod.verify_checkpoint(rec_end):
        return VerificationResult(valid=False, proof_id=proof_id, reason="VERIFY_FAILED: INVALID_ANCHOR_SIGNATURE: end_anchor signature invalid", checks=checks)

    checks["anchor_sigs"] = True

    # 5. CHECK_ANCHOR_BOUNDS
    if rec_start.timestamp > w_start:
        return VerificationResult(valid=False, proof_id=proof_id, reason=f"VERIFY_FAILED: UNBOUNDED_WINDOW: start anchor ts ({rec_start.timestamp}) > window start ({w_start})", checks=checks)
    if rec_end.timestamp < w_end:
        return VerificationResult(valid=False, proof_id=proof_id, reason=f"VERIFY_FAILED: UNBOUNDED_WINDOW: end anchor ts ({rec_end.timestamp}) < window end ({w_end})", checks=checks)
    if rec_start.seq > rec_end.seq:
        return VerificationResult(valid=False, proof_id=proof_id, reason=f"VERIFY_FAILED: UNBOUNDED_WINDOW: start anchor seq {rec_start.seq} > end anchor seq {rec_end.seq}", checks=checks)

    checks["anchor_bounds"] = True

    # 6. CHECK_BLOOM_EXCLUSION
    segments = data.get("segments_checked", [])
    for seg in segments:
        m = seg.get("bloom_m_bits")
        k = seg.get("bloom_k")
        bhex = seg.get("bloom_hex")
        if not m or not k or not bhex:
            # If segment was recorded with bloom_negative=True but without embedded hex,
            # verify that bloom_negative was certified
            if not seg.get("bloom_negative", False):
                return VerificationResult(valid=False, proof_id=proof_id, reason=f"VERIFY_FAILED: BLOOM_POSITIVE: segment {seg.get('segment_id')} not negative", checks=checks)
        else:
            bits = bytes.fromhex(bhex)
            if retention_mod.bloom_test(bits, m, k, grant_id):
                return VerificationResult(valid=False, proof_id=proof_id, reason=f"VERIFY_FAILED: BLOOM_INDICATES_PRESENCE: segment {seg.get('segment_id')} bloom matches grant {grant_id}", checks=checks)

    checks["bloom_exclusion"] = True

    # 7. CHECK_LIVE_CHAIN
    live_range = data.get("live_range", {})
    hashes = live_range.get("hashes", [])
    if hashes:
        last_hash = hashes[-1]
        if last_hash != rec_end.head_hash:
            return VerificationResult(valid=False, proof_id=proof_id, reason=f"VERIFY_FAILED: HEAD_HASH_MISMATCH: chain tail {last_hash} != anchor head_hash {rec_end.head_hash}", checks=checks)

    checks["live_chain"] = True

    return VerificationResult(valid=True, proof_id=proof_id, reason=None, checks=checks)


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: python -m aiosh_mcp.verifier <proof_file.json> --pubkey <hex> [--pubkey <hex2>...]", file=sys.stderr)
        return 1

    proof_path = sys.argv[1]
    pubkeys: list[str] = []
    args = sys.argv[2:]
    for idx, arg in enumerate(args):
        if arg == "--pubkey" and idx + 1 < len(args):
            pubkeys.append(args[idx + 1])

    if not pubkeys:
        print("Error: at least one --pubkey must be specified", file=sys.stderr)
        return 1

    result = verify_restraint_proof(proof_path, pubkeys)
    print(result.to_canonical_json())
    return 0 if result.valid else 1


if __name__ == "__main__":
    sys.exit(main())
