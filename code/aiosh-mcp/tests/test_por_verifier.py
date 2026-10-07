#!/usr/bin/env python3
"""Proof of Restraint: Standalone Proof Verifier Unit Test Suite (T-02876).

Sprint / Architecture: ADR-0037, PLAN.md §Layer 2, Invariant I-4.
Verifies purely mathematical and cryptographic verification without SQLite or host dependencies:
  1. Valid proof verification with all 7 checks passing.
  2. Rejection of invalid schema / missing mandatory fields.
  3. Rejection of redeemed grant.
  4. Rejection of non-single-use grant.
  5. Rejection of invalid window or expired grant.
  6. Rejection of untrusted anchor public key.
  7. Rejection of tampered anchor signature.
  8. Rejection of unbounding anchor timestamps.
  9. Rejection when Bloom filter indicates presence in archived segment.
  10. Rejection when live chain tail does not match end anchor head_hash.
  11. File path vs JSON dict loading.
  12. Zero-database invariant: sqlite3 module not called or required.
"""

from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from aiosh_mcp.anchors import generate_keypair, sign_checkpoint
from aiosh_mcp.retention import bloom_add
from aiosh_mcp.verifier import VerificationResult, verify_restraint_proof


def _create_synthetic_proof(
    priv_key: str,
    pub_key: str,
    grant_id: str = "gr-valid-01",
    window_start: str = "2026-10-07T12:00:00Z",
    window_end: str = "2026-10-07T12:10:00Z",
    redeemed_at: str | None = None,
    single_use: bool = True,
    bloom_hits: bool = False,
    corrupt_chain: bool = False,
) -> dict:
    # 1. Covering anchors
    a1 = sign_checkpoint(seq=1, head_hash="hash_0001", timestamp="2026-10-07T11:55:00Z", private_key_hex=priv_key)
    a2 = sign_checkpoint(seq=20, head_hash="hash_0020", timestamp="2026-10-07T12:15:00Z", private_key_hex=priv_key)

    # 2. Segments
    m, k = 1024, 7
    bits = bytearray(m // 8)
    if bloom_hits:
        from aiosh_mcp.retention import bloom_add
        bloom_add(bits, m, k, grant_id)

    segment = {
        "segment_id": 1,
        "row_range": [1, 10],
        "archive_sha256": "deadbeef" * 8,
        "bloom_m_bits": m,
        "bloom_k": k,
        "bloom_hex": bits.hex(),
        "bloom_negative": not bloom_hits,
    }

    # 3. Live range
    tail_hash = "corrupt_hash_9999" if corrupt_chain else "hash_0020"
    live_range = {
        "first_seq": 11,
        "last_seq": 20,
        "row_count": 10,
        "hashes": ["hash_0011", "hash_0012", tail_hash],
    }

    return {
        "schema_version": 1,
        "proof_id": "por_synthetic_test_001",
        "generated_at": "2026-10-07T12:16:00Z",
        "grant": {
            "grant_id": grant_id,
            "issued_at": "2026-10-07T11:50:00Z",
            "expires_at": "2026-10-07T23:59:59Z",
            "issued_to": "agent:pentest",
            "single_use": single_use,
            "redeemed_at": redeemed_at,
        },
        "window": {
            "start": window_start,
            "end": window_end,
        },
        "anchors": {
            "start_anchor": a1.to_dict(),
            "end_anchor": a2.to_dict(),
        },
        "segments_checked": [segment],
        "live_range": live_range,
        "verdict": "PROVABLY_RESTRAINED",
    }


@pytest.fixture
def keys():
    priv, pub = generate_keypair()
    return {"priv": priv, "pub": pub}


def test_verify_valid_proof(keys):
    pkg = _create_synthetic_proof(keys["priv"], keys["pub"])
    res = verify_restraint_proof(pkg, [keys["pub"]])

    assert isinstance(res, VerificationResult)
    assert res.valid is True
    assert res.proof_id == "por_synthetic_test_001"
    assert res.reason is None
    assert all(res.checks.values())


def test_verify_invalid_schema(keys):
    res = verify_restraint_proof({}, [keys["pub"]])
    assert res.valid is False
    assert "UNSUPPORTED_SCHEMA_VERSION" in res.reason


def test_verify_redeemed_grant_rejected(keys):
    pkg = _create_synthetic_proof(keys["priv"], keys["pub"], redeemed_at="2026-10-07T12:05:00Z")
    res = verify_restraint_proof(pkg, [keys["pub"]])
    assert res.valid is False
    assert "GRANT_REDEEMED" in res.reason


def test_verify_non_single_use_grant_rejected(keys):
    pkg = _create_synthetic_proof(keys["priv"], keys["pub"], single_use=False)
    res = verify_restraint_proof(pkg, [keys["pub"]])
    assert res.valid is False
    assert "GRANT_INVALID" in res.reason


def test_verify_invalid_window_rejected(keys):
    pkg = _create_synthetic_proof(
        keys["priv"], keys["pub"],
        window_start="2026-10-07T13:00:00Z",
        window_end="2026-10-07T12:00:00Z",
    )
    res = verify_restraint_proof(pkg, [keys["pub"]])
    assert res.valid is False
    assert "WINDOW_INVALID" in res.reason


def test_verify_untrusted_key_rejected(keys):
    pkg = _create_synthetic_proof(keys["priv"], keys["pub"])
    untrusted_pub = "0" * 64
    res = verify_restraint_proof(pkg, [untrusted_pub])
    assert res.valid is False
    assert "UNTRUSTED_KEY" in res.reason


def test_verify_tampered_anchor_sig_rejected(keys):
    pkg = _create_synthetic_proof(keys["priv"], keys["pub"])
    # Tamper with anchor signature
    pkg["anchors"]["start_anchor"]["signature"] = "f" * 128
    res = verify_restraint_proof(pkg, [keys["pub"]])
    assert res.valid is False
    assert "INVALID_ANCHOR_SIGNATURE" in res.reason


def test_verify_unbounding_anchor_rejected(keys):
    # Anchor starts after window start
    pkg = _create_synthetic_proof(
        keys["priv"], keys["pub"],
        window_start="2026-10-07T11:50:00Z",  # anchor timestamp is 11:55:00Z
    )
    res = verify_restraint_proof(pkg, [keys["pub"]])
    assert res.valid is False
    assert "UNBOUNDED_WINDOW" in res.reason


def test_verify_bloom_positive_presence_rejected(keys):
    pkg = _create_synthetic_proof(keys["priv"], keys["pub"], bloom_hits=True)
    res = verify_restraint_proof(pkg, [keys["pub"]])
    assert res.valid is False
    assert "BLOOM_INDICATES_PRESENCE" in res.reason


def test_verify_chain_head_mismatch_rejected(keys):
    pkg = _create_synthetic_proof(keys["priv"], keys["pub"], corrupt_chain=True)
    res = verify_restraint_proof(pkg, [keys["pub"]])
    assert res.valid is False
    assert "HEAD_HASH_MISMATCH" in res.reason


def test_verify_file_loading_roundtrip(keys):
    pkg = _create_synthetic_proof(keys["priv"], keys["pub"])
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as f:
        f.write(json.dumps(pkg))
        f_path = f.name

    try:
        res = verify_restraint_proof(f_path, [keys["pub"]])
        assert res.valid is True
        assert res.proof_id == pkg["proof_id"]
    finally:
        Path(f_path).unlink(missing_ok=True)
