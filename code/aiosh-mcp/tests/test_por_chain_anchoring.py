#!/usr/bin/env python3
"""Proof of Restraint: Chain Anchoring & Completeness Checkpoints Unit Test (T-02856).

Verifies Invariant I-3:
  1. Key generation emits 64-hex private and public Ed25519 keys.
  2. Signing chain checkpoints creates valid AnchorRecords with canonical payloads.
  3. Signature verification succeeds on authentic records and rejects corrupt/tampered signatures.
  4. Modifying seq, head_hash, or timestamp invalidates the signature.
  5. Chain verification against external anchors succeeds on genuine complete chains.
  6. Truncated chain (dropping recent rows) fails verification with TRUNCATION_DETECTED.
  7. Rewritten chain (forked/modified hashes) fails verification with FORK_DETECTED.
  8. Untrusted anchor pubkey fails verification with UNTRUSTED_KEY.
  9. File persistence: append_anchor and load_anchors roundtrips successfully.
  10. Key separation: audit DB does not store private signing keys.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from aiosh_mcp.anchors import (
    AnchorRecord,
    generate_keypair,
    sign_checkpoint,
    verify_checkpoint,
    append_anchor,
    load_anchors,
    verify_chain_against_anchors,
)
from aiosh_mcp import audit_client


def test_keypair_generation():
    priv, pub = generate_keypair()
    assert len(priv) == 64, f"Expected 64 hex chars private key, got {len(priv)}"
    assert len(pub) == 64, f"Expected 64 hex chars public key, got {len(pub)}"
    # Keys must be valid hex
    bytes.fromhex(priv)
    bytes.fromhex(pub)


def test_sign_and_verify_checkpoint():
    priv, pub = generate_keypair()
    anchor = sign_checkpoint(
        seq=42,
        head_hash="4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        timestamp="2026-10-07T12:00:00Z",
        private_key_hex=priv,
    )
    assert anchor.seq == 42
    assert anchor.pubkey == pub
    assert len(anchor.signature) == 128  # 64 bytes in hex
    assert verify_checkpoint(anchor) is True


def test_tampered_anchor_detection():
    priv, pub = generate_keypair()
    anchor = sign_checkpoint(
        seq=50,
        head_hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        timestamp="2026-10-07T12:00:00Z",
        private_key_hex=priv,
    )

    # Tampered sequence
    tampered_seq = AnchorRecord(
        anchor.schema_version,
        51,
        anchor.head_hash,
        anchor.timestamp,
        anchor.pubkey,
        anchor.signature,
    )
    assert verify_checkpoint(tampered_seq) is False

    # Tampered head hash
    tampered_hash = AnchorRecord(
        anchor.schema_version,
        anchor.seq,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        anchor.timestamp,
        anchor.pubkey,
        anchor.signature,
    )
    assert verify_checkpoint(tampered_hash) is False

    # Tampered timestamp
    tampered_ts = AnchorRecord(
        anchor.schema_version,
        anchor.seq,
        anchor.head_hash,
        "2026-10-07T12:00:01Z",
        anchor.pubkey,
        anchor.signature,
    )
    assert verify_checkpoint(tampered_ts) is False

    # Corrupt signature
    corrupt_sig = AnchorRecord(
        anchor.schema_version,
        anchor.seq,
        anchor.head_hash,
        anchor.timestamp,
        anchor.pubkey,
        "00" * 64,
    )
    assert verify_checkpoint(corrupt_sig) is False


def test_chain_verification_against_anchors_happy_path():
    priv, pub = generate_keypair()
    chain = [{"id": i, "hash": f"hash_{i:04d}"} for i in range(1, 101)]

    # Create checkpoints at seq 25, 50, 100
    a25 = sign_checkpoint(25, chain[24]["hash"], "2026-10-07T12:25:00Z", priv)
    a50 = sign_checkpoint(50, chain[49]["hash"], "2026-10-07T12:50:00Z", priv)
    a100 = sign_checkpoint(100, chain[99]["hash"], "2026-10-07T13:00:00Z", priv)

    valid, err = verify_chain_against_anchors(chain, [a25, a50, a100], trusted_pubkey=pub)
    assert valid is True
    assert err is None


def test_chain_truncation_detection():
    priv, pub = generate_keypair()
    full_chain = [{"id": i, "hash": f"hash_{i:04d}"} for i in range(1, 101)]
    anchor_100 = sign_checkpoint(100, full_chain[99]["hash"], "2026-10-07T13:00:00Z", priv)

    # Attacker presents truncated chain with only 80 rows
    truncated_chain = full_chain[:80]
    valid, err = verify_chain_against_anchors(truncated_chain, [anchor_100], trusted_pubkey=pub)
    assert valid is False
    assert err is not None
    assert "TRUNCATION_DETECTED" in err


def test_chain_fork_and_rewrite_detection():
    priv, pub = generate_keypair()
    chain = [{"id": i, "hash": f"hash_{i:04d}"} for i in range(1, 101)]
    anchor_50 = sign_checkpoint(50, chain[49]["hash"], "2026-10-07T12:50:00Z", priv)

    # Attacker rewrites row 50
    forked_chain = list(chain)
    forked_chain[49] = {"id": 50, "hash": "alternate_hash_from_rewritten_history"}

    valid, err = verify_chain_against_anchors(forked_chain, [anchor_50], trusted_pubkey=pub)
    assert valid is False
    assert err is not None
    assert "FORK_DETECTED" in err


def test_untrusted_pubkey_rejection():
    priv1, pub1 = generate_keypair()
    _priv2, pub2 = generate_keypair()

    chain = [{"id": 1, "hash": "hash_0001"}]
    anchor = sign_checkpoint(1, "hash_0001", "2026-10-07T12:00:00Z", priv1)

    # Verifying with trusted_pubkey pub2 while anchor was signed by pub1
    valid, err = verify_chain_against_anchors(chain, [anchor], trusted_pubkey=pub2)
    assert valid is False
    assert err is not None
    assert "UNTRUSTED_KEY" in err


def test_anchor_persistence_roundtrip():
    with tempfile.TemporaryDirectory() as tmp_dir:
        anchors_file = Path(tmp_dir) / "anchors.jsonl"
        priv, _pub = generate_keypair()

        a1 = sign_checkpoint(10, "h10", "2026-10-07T10:00:00Z", priv)
        a2 = sign_checkpoint(20, "h20", "2026-10-07T10:10:00Z", priv)

        append_anchor(a1, anchors_file)
        append_anchor(a2, anchors_file)

        loaded = load_anchors(anchors_file)
        assert len(loaded) == 2
        assert loaded[0] == a1
        assert loaded[1] == a2


def test_key_separation_invariant():
    """Verify that audit.db schema does not contain private key columns."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "audit.db"
        conn = sqlite3.connect(db_path)
        try:
            audit_client.ensure_audit_schema(conn)
            cursor = conn.execute("PRAGMA table_info(audit_ring)")
            col_names = [row[1].lower() for row in cursor.fetchall()]

            for forbidden in ["priv", "private", "key", "secret", "signer"]:
                assert not any(forbidden in col for col in col_names), (
                    f"Forbidden key material column found in audit_ring: {col_names}"
                )
        finally:
            conn.close()


if __name__ == "__main__":
    test_keypair_generation()
    test_sign_and_verify_checkpoint()
    test_tampered_anchor_detection()
    test_chain_verification_against_anchors_happy_path()
    test_chain_truncation_detection()
    test_chain_fork_and_rewrite_detection()
    test_untrusted_pubkey_rejection()
    test_anchor_persistence_roundtrip()
    test_key_separation_invariant()
    print("ALL T-02856 UNIT TESTS PASSED!")
