#!/usr/bin/env python3
"""Proof of Restraint: Standalone Proof Verifier Integration Test Suite (T-02877).

Sprint / Architecture: ADR-0037, PLAN.md §Layer 2, Invariant I-4.
Verifies end-to-end integration between Proof Generator and Standalone Verifier:
  1. Complete flow: Mint grant -> Anchor WAL -> Generate proof -> Standalone verify.
  2. MCP Tool integration: `aios.restraint.verify` tool validates proof packages.
  3. Anti-tampering: modified or forged proofs fail verification across all surfaces.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from aiosh_mcp.anchors import append_anchor, generate_keypair, sign_checkpoint
from aiosh_mcp import audit_client
from aiosh_mcp.restraint import generate_restraint_proof
from aiosh_mcp.verifier import verify_restraint_proof
from aiosh_mcp import server as mcp_server


@pytest.fixture
def end_to_end_env():
    tmp_path = Path(tempfile.mkdtemp(prefix="por-verify-int-"))
    aiosh_home = tmp_path / ".aios"
    aiosh_home.mkdir(parents=True, exist_ok=True)
    anchors_dir = aiosh_home / "anchors"
    anchors_dir.mkdir(parents=True, exist_ok=True)

    db_path = aiosh_home / "audit.db"
    anchors_path = anchors_dir / "anchors.jsonl"

    old_home = os.environ.get("AIOSH_HOME")
    os.environ["AIOSH_HOME"] = str(aiosh_home)

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        audit_client.ensure_audit_schema(conn)
        audit_client.ensure_pep_schema(conn)

        for i in range(1, 6):
            ts = f"2026-10-07T12:0{i}:00Z"
            audit_client.write_audit_row(conn, {
                "ts": ts,
                "actor": "user",
                "actor_id": "admin",
                "tool": "aios.fs.read",
                "command": f"cat file_{i}",
                "args": {"path": f"/tmp/file_{i}"},
                "target": f"/tmp/file_{i}",
                "outcome": "ok",
                "outcome_detail": None,
                "constitution_rev": "rev1",
                "grant_token": None,
                "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True},
            })

        conn.execute(
            """INSERT INTO pep_grants (
                grant_id, issued_at, expires_at, issued_to, constitution_rev,
                scope_json, scope_hash, single_use
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
            (
                "grant-verify-int-99",
                "2026-10-07T12:00:00Z",
                "2026-10-07T23:59:59Z",
                "agent:verifier",
                "rev-verify",
                json.dumps({"capabilities": ["ledger.read"]}),
                "hash-verify",
            ),
        )
        conn.commit()

        # Get tail hash for end anchor
        cur = conn.execute("SELECT hash FROM audit_ring WHERE id = 5")
        tail_hash = cur.fetchone()[0]

    priv, pub = generate_keypair()
    a1 = sign_checkpoint(seq=1, head_hash="hash_placeholder_1", timestamp="2026-10-07T12:00:00Z", private_key_hex=priv)
    a2 = sign_checkpoint(seq=5, head_hash=tail_hash, timestamp="2026-10-07T12:10:00Z", private_key_hex=priv)
    append_anchor(a1, anchors_path)
    append_anchor(a2, anchors_path)

    yield {
        "db_path": db_path,
        "anchors_path": anchors_path,
        "priv": priv,
        "pub": pub,
    }

    if old_home is not None:
        os.environ["AIOSH_HOME"] = old_home
    else:
        os.environ.pop("AIOSH_HOME", None)

    shutil.rmtree(tmp_path, ignore_errors=True)


def test_generator_to_verifier_end_to_end(end_to_end_env):
    with sqlite3.connect(str(end_to_end_env["db_path"])) as conn:
        conn.row_factory = sqlite3.Row
        proof = generate_restraint_proof(
            conn=conn,
            grant_id="grant-verify-int-99",
            window_start="2026-10-07T12:01:00Z",
            window_end="2026-10-07T12:05:00Z",
            anchors_path=str(end_to_end_env["anchors_path"]),
        )

    # Standalone verification with trusted key
    res = verify_restraint_proof(proof.to_dict(), [end_to_end_env["pub"]])
    assert res.valid is True
    assert res.proof_id == proof.proof_id
    assert res.reason is None
    assert all(res.checks.values())


def test_mcp_restraint_verify_tool_integration(end_to_end_env):
    with sqlite3.connect(str(end_to_end_env["db_path"])) as conn:
        conn.row_factory = sqlite3.Row
        proof = generate_restraint_proof(
            conn=conn,
            grant_id="grant-verify-int-99",
            window_start="2026-10-07T12:01:00Z",
            window_end="2026-10-07T12:05:00Z",
            anchors_path=str(end_to_end_env["anchors_path"]),
        )

    res = mcp_server.aios_restraint_verify(
        proof=proof.to_dict(),
        trusted_pubkeys=[end_to_end_env["pub"]],
    )
    assert res["ok"] is True
    assert res["tool"] == "aios.restraint.verify"
    assert res["result"]["valid"] is True


def test_mcp_restraint_verify_tampered_detection(end_to_end_env):
    with sqlite3.connect(str(end_to_end_env["db_path"])) as conn:
        conn.row_factory = sqlite3.Row
        proof = generate_restraint_proof(
            conn=conn,
            grant_id="grant-verify-int-99",
            window_start="2026-10-07T12:01:00Z",
            window_end="2026-10-07T12:05:00Z",
            anchors_path=str(end_to_end_env["anchors_path"]),
        )

    tampered = proof.to_dict()
    # Forge window to be wider than anchor bounds
    tampered["window"]["start"] = "2026-10-07T11:00:00Z"

    res = mcp_server.aios_restraint_verify(
        proof=tampered,
        trusted_pubkeys=[end_to_end_env["pub"]],
    )
    assert res["ok"] is False
    assert res["result"]["valid"] is False
    assert "VERIFY_FAILED" in res["result"]["reason"]

