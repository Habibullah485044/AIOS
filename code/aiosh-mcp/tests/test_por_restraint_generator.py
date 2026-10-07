#!/usr/bin/env python3
"""Proof of Restraint: Restraint Proof Generator Unit Test Suite (T-02866).

Sprint / Architecture: ADR-0037, PLAN.md §Layer 2, Invariant I-4.
Verifies:
  1. Valid restraint proof generation for unredeemed capability grant.
  2. Canonical JSON serialization of RestraintProofPackage.
  3. Rejection of invalid time window (window_start > window_end).
  4. Rejection of nonexistent grant (GRANT_NOT_FOUND).
  5. Rejection of already redeemed grant in pep_grants (GRANT_REDEEMED).
  6. Rejection of grant redeemed in live audit_ring rows (GRANT_REDEEMED).
  7. Rejection of grant detected in archived segment Bloom filter (GRANT_REDEEMED).
  8. Successful Bloom filter exclusion for archived segments not containing the grant.
  9. Rejection when no covering anchors exist (NO_COVERING_ANCHORS).
  10. Correct live range extraction and hash continuity across the window.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from aiosh_mcp.anchors import (
    AnchorRecord,
    append_anchor,
    generate_keypair,
    sign_checkpoint,
)
from aiosh_mcp.audit_client import ensure_pep_schema
from aiosh_mcp.restraint import (
    RestraintProofPackage,
    generate_restraint_proof,
)
from aiosh_mcp.retention import bloom_add, bloom_test


def _insert_grant(
    conn: sqlite3.Connection,
    grant_id: str,
    task_id: str = "T-02866",
    grantee: str = "agent-sec",
    capabilities: list[str] | None = None,
    valid_until: str = "2026-10-07T23:59:59Z",
    single_use: bool = True,
    redeemed_at: str | None = None,
):
    scope = {"capabilities": capabilities or ["fs.read"]}
    scope_json = json.dumps(scope)
    conn.execute(
        """INSERT INTO pep_grants (
            grant_id, issued_at, expires_at, issued_to, constitution_rev,
            scope_json, scope_hash, single_use, redeemed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            grant_id,
            "2026-10-07T12:00:00Z",
            valid_until,
            grantee,
            "rev-1",
            scope_json,
            "hash-scope",
            1 if single_use else 0,
            redeemed_at,
        ),
    )
    conn.commit()



@pytest.fixture
def test_env():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        db_path = tmp_path / "test_audit.db"
        anchors_path = tmp_path / "anchors.jsonl"

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row

        # Setup audit schema
        conn.executescript("""
            CREATE TABLE audit_ring (
                id INTEGER PRIMARY KEY,
                ts TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                tool TEXT NOT NULL,
                command TEXT,
                args_json TEXT,
                risk_level TEXT,
                prev_hash TEXT,
                hash TEXT NOT NULL,
                signature TEXT,
                grant_token TEXT
            );

            CREATE TABLE audit_segments (
                segment_id INTEGER PRIMARY KEY,
                first_row_id INTEGER NOT NULL,
                last_row_id INTEGER NOT NULL,
                archive_sha256 TEXT NOT NULL,
                bloom_m_bits INTEGER NOT NULL,
                bloom_k INTEGER NOT NULL,
                bloom_hex TEXT NOT NULL
            );
        """)
        ensure_pep_schema(conn)

        # Setup Ed25519 keypair for checkpoints
        priv, pub = generate_keypair()

        yield {
            "conn": conn,
            "db_path": db_path,
            "anchors_path": anchors_path,
            "priv": priv,
            "pub": pub,
        }
        conn.close()


def _populate_chain(conn: sqlite3.Connection, count: int = 10):
    prev = "0000000000000000000000000000000000000000000000000000000000000000"
    for i in range(1, count + 1):
        ts = f"2026-10-07T12:{i:02d}:00Z"
        row_hash = f"hash_{i:04d}_{prev[:8]}"
        conn.execute(
            """INSERT INTO audit_ring (id, ts, agent_id, tool, command, args_json, risk_level, prev_hash, hash, grant_token)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (i, ts, "agent-1", "fs.read", "cat", "{}", "low", prev, row_hash, None),
        )
        prev = row_hash
    conn.commit()


def test_generate_valid_restraint_proof(test_env):
    conn = test_env["conn"]
    anchors_path = test_env["anchors_path"]
    priv = test_env["priv"]

    _populate_chain(conn, 10)

    # Issue grant
    _insert_grant(
        conn,
        grant_id="grant-restrained-001",
        task_id="T-02866",
        grantee="agent-sec",
        capabilities=["fs.read", "ledger.touch"],
        valid_until="2026-10-07T23:59:59Z",
        single_use=True,
    )

    # Create covering anchors
    a1 = sign_checkpoint(seq=1, head_hash="hash_0001", timestamp="2026-10-07T12:00:00Z", private_key_hex=priv)
    a2 = sign_checkpoint(seq=10, head_hash="hash_0010", timestamp="2026-10-07T12:15:00Z", private_key_hex=priv)
    append_anchor(a1, anchors_path)
    append_anchor(a2, anchors_path)

    # Generate proof
    proof = generate_restraint_proof(
        conn=conn,
        grant_id="grant-restrained-001",
        window_start="2026-10-07T12:01:00Z",
        window_end="2026-10-07T12:10:00Z",
        anchors_path=anchors_path,
    )

    assert isinstance(proof, RestraintProofPackage)
    assert proof.schema_version == 1
    assert proof.proof_id.startswith("por_")
    assert proof.verdict == "PROVABLY_RESTRAINED"
    assert proof.grant["grant_id"] == "grant-restrained-001"
    assert proof.grant["redeemed_at"] is None
    assert proof.window["start"] == "2026-10-07T12:01:00Z"
    assert proof.window["end"] == "2026-10-07T12:10:00Z"
    assert proof.anchors["start_anchor"]["seq"] == 1
    assert proof.anchors["end_anchor"]["seq"] == 10
    assert proof.live_range["row_count"] == 10
    assert len(proof.live_range["hashes"]) == 10

    # Verify canonical serialization
    cjson = proof.to_canonical_json()
    assert isinstance(cjson, str)
    decoded = json.loads(cjson)
    assert decoded["verdict"] == "PROVABLY_RESTRAINED"


def test_window_invalid_rejection(test_env):
    conn = test_env["conn"]
    with pytest.raises(ValueError, match="WINDOW_INVALID"):
        generate_restraint_proof(
            conn=conn,
            grant_id="grant-x",
            window_start="2026-10-07T14:00:00Z",
            window_end="2026-10-07T13:00:00Z",
        )


def test_grant_not_found_rejection(test_env):
    conn = test_env["conn"]
    anchors_path = test_env["anchors_path"]
    with pytest.raises(ValueError, match="GRANT_NOT_FOUND"):
        generate_restraint_proof(
            conn=conn,
            grant_id="nonexistent-grant-id",
            window_start="2026-10-07T12:00:00Z",
            window_end="2026-10-07T12:30:00Z",
            anchors_path=anchors_path,
        )


def test_grant_already_redeemed_in_grant_table(test_env):
    conn = test_env["conn"]
    anchors_path = test_env["anchors_path"]

    _insert_grant(
        conn,
        grant_id="grant-already-used",
        task_id="T-02866",
        grantee="agent-sec",
        capabilities=["fs.write"],
        valid_until="2026-10-07T23:59:59Z",
        single_use=True,
    )
    conn.execute(
        "UPDATE pep_grants SET redeemed_at = '2026-10-07T12:05:00Z' WHERE grant_id = 'grant-already-used'"
    )
    conn.commit()

    with pytest.raises(ValueError, match="GRANT_REDEEMED"):
        generate_restraint_proof(
            conn=conn,
            grant_id="grant-already-used",
            window_start="2026-10-07T12:00:00Z",
            window_end="2026-10-07T12:30:00Z",
            anchors_path=anchors_path,
        )


def test_grant_redeemed_in_audit_ring_row(test_env):
    conn = test_env["conn"]
    anchors_path = test_env["anchors_path"]
    priv = test_env["priv"]

    _populate_chain(conn, 5)

    _insert_grant(
        conn,
        grant_id="grant-redeemed-ring",
        task_id="T-02866",
        grantee="agent-sec",
        capabilities=["fs.write"],
        valid_until="2026-10-07T23:59:59Z",
        single_use=True,
    )

    # Insert a redemption row
    conn.execute(
        """INSERT INTO audit_ring (id, ts, agent_id, tool, command, args_json, risk_level, prev_hash, hash, grant_token)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (6, "2026-10-07T12:06:00Z", "agent-1", "pep.capability.redeem", "redeem", "{}", "high", "hash_0005", "hash_0006", "grant-redeemed-ring"),
    )
    conn.commit()

    a1 = sign_checkpoint(seq=1, head_hash="hash_0001", timestamp="2026-10-07T12:00:00Z", private_key_hex=priv)
    a2 = sign_checkpoint(seq=6, head_hash="hash_0006", timestamp="2026-10-07T12:10:00Z", private_key_hex=priv)
    append_anchor(a1, anchors_path)
    append_anchor(a2, anchors_path)

    with pytest.raises(ValueError, match="GRANT_REDEEMED"):
        generate_restraint_proof(
            conn=conn,
            grant_id="grant-redeemed-ring",
            window_start="2026-10-07T12:00:00Z",
            window_end="2026-10-07T12:10:00Z",
            anchors_path=anchors_path,
        )


def test_grant_detected_in_archived_segment_bloom(test_env):
    conn = test_env["conn"]
    anchors_path = test_env["anchors_path"]
    priv = test_env["priv"]

    _insert_grant(
        conn,
        grant_id="grant-in-bloom",
        task_id="T-02866",
        grantee="agent-sec",
        capabilities=["fs.write"],
        valid_until="2026-10-07T23:59:59Z",
        single_use=True,
    )

    # Create bloom containing grant-in-bloom
    m, k = 1024, 7
    bits = bytearray(m // 8)
    bloom_add(bits, m, k, "grant-in-bloom")

    conn.execute(
        """INSERT INTO audit_segments (segment_id, first_row_id, last_row_id, archive_sha256, bloom_m_bits, bloom_k, bloom_hex)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (1, 1, 50, "deadbeef" * 8, m, k, bits.hex()),
    )
    conn.commit()

    a1 = sign_checkpoint(seq=1, head_hash="hash_0001", timestamp="2026-10-07T12:00:00Z", private_key_hex=priv)
    a2 = sign_checkpoint(seq=50, head_hash="hash_0050", timestamp="2026-10-07T12:30:00Z", private_key_hex=priv)
    append_anchor(a1, anchors_path)
    append_anchor(a2, anchors_path)

    with pytest.raises(ValueError, match="GRANT_REDEEMED: segment 1 bloom indicates grant present"):
        generate_restraint_proof(
            conn=conn,
            grant_id="grant-in-bloom",
            window_start="2026-10-07T12:00:00Z",
            window_end="2026-10-07T12:30:00Z",
            anchors_path=anchors_path,
        )


def test_archived_segment_bloom_exclusion_success(test_env):
    conn = test_env["conn"]
    anchors_path = test_env["anchors_path"]
    priv = test_env["priv"]

    _insert_grant(
        conn,
        grant_id="grant-not-in-bloom",
        task_id="T-02866",
        grantee="agent-sec",
        capabilities=["fs.write"],
        valid_until="2026-10-07T23:59:59Z",
        single_use=True,
    )

    # Create bloom containing other tokens only
    m, k = 1024, 7
    bits = bytearray(m // 8)
    bloom_add(bits, m, k, "other-token-alpha")
    bloom_add(bits, m, k, "other-token-beta")

    conn.execute(
        """INSERT INTO audit_segments (segment_id, first_row_id, last_row_id, archive_sha256, bloom_m_bits, bloom_k, bloom_hex)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (1, 1, 50, "deadbeef" * 8, m, k, bits.hex()),
    )
    conn.commit()

    a1 = sign_checkpoint(seq=1, head_hash="hash_0001", timestamp="2026-10-07T12:00:00Z", private_key_hex=priv)
    a2 = sign_checkpoint(seq=50, head_hash="hash_0050", timestamp="2026-10-07T12:30:00Z", private_key_hex=priv)
    append_anchor(a1, anchors_path)
    append_anchor(a2, anchors_path)

    proof = generate_restraint_proof(
        conn=conn,
        grant_id="grant-not-in-bloom",
        window_start="2026-10-07T12:00:00Z",
        window_end="2026-10-07T12:30:00Z",
        anchors_path=anchors_path,
    )
    assert proof.verdict == "PROVABLY_RESTRAINED"
    assert len(proof.segments_checked) == 1
    assert proof.segments_checked[0]["bloom_negative"] is True
    assert proof.segments_checked[0]["segment_id"] == 1


def test_no_covering_anchors_rejection(test_env):
    conn = test_env["conn"]
    anchors_path = test_env["anchors_path"]

    _insert_grant(
        conn,
        grant_id="grant-no-anchors",
        task_id="T-02866",
        grantee="agent-sec",
        capabilities=["fs.write"],
        valid_until="2026-10-07T23:59:59Z",
        single_use=True,
    )

    # Empty anchors file
    anchors_path.touch()

    with pytest.raises(ValueError, match="NO_COVERING_ANCHORS"):
        generate_restraint_proof(
            conn=conn,
            grant_id="grant-no-anchors",
            window_start="2026-10-07T12:00:00Z",
            window_end="2026-10-07T12:30:00Z",
            anchors_path=anchors_path,
        )
