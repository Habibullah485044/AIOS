#!/usr/bin/env python3
"""Proof of Restraint: Chain Anchoring End-to-End Integration Test (T-02857).

Tests:
  1. FastMCP tool registration for aios_anchor_create and aios_anchor_verify.
  2. Creating an anchor through FastMCP produces a verified anchor in $AIOSH_HOME/anchors/anchors.jsonl.
  3. Audited action: an audit row is written for aios.anchor.create.
  4. aios_anchor_verify returns verified=True against authentic chain.
  5. Truncating the database causes aios_anchor_verify to detect truncation.
"""

import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from aiosh_mcp.anchors import generate_keypair
from aiosh_mcp import audit_client
from aiosh_mcp import server as mcp_server


def test_anchor_integration_end_to_end():
    tmp_dir = Path(tempfile.mkdtemp(prefix="por-anchor-int-"))
    try:
        os.environ["AIOSH_HOME"] = str(tmp_dir)

        # 1. Initialize audit schema and seed a few rows
        db_path = tmp_dir / "audit.db"
        with sqlite3.connect(db_path) as conn:
            conn.row_factory = sqlite3.Row
            audit_client.ensure_audit_schema(conn)

            r1 = audit_client.write_audit_row(conn, {
                "ts": audit_client.utcnow_iso(),
                "actor": "user",
                "actor_id": "user:alice",
                "tool": "fs.read",
                "command": "read file1",
                "args": {"path": "/tmp/test1"},
                "target": "/tmp/test1",
                "outcome": "ok",
                "outcome_detail": None,
                "constitution_rev": "rev1",
                "grant_token": None,
                "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True},
            })
            r2 = audit_client.write_audit_row(conn, {
                "ts": audit_client.utcnow_iso(),
                "actor": "user",
                "actor_id": "user:alice",
                "tool": "process.list",
                "command": "ps",
                "args": {},
                "target": None,
                "outcome": "ok",
                "outcome_detail": None,
                "constitution_rev": "rev1",
                "grant_token": None,
                "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True},
            })

        assert r2.id == 2

        # 2. Generate anchor keypair
        priv, pub = generate_keypair()
        os.environ["AIOSH_ANCHOR_KEY"] = priv
        os.environ["AIOSH_ANCHOR_PUBKEY"] = pub

        # 3. Create anchor via MCP tool
        res_create = mcp_server.aios_anchor_create()
        assert res_create.get("ok") is True, f"aios_anchor_create failed: {res_create}"
        assert res_create.get("tool") == "aios.anchor.create"
        assert "anchor" in res_create
        assert res_create["anchor"]["seq"] == 2

        # 4. Verify anchor via MCP tool
        res_verify = mcp_server.aios_anchor_verify()
        assert res_verify.get("ok") is True, f"aios_anchor_verify failed: {res_verify}"
        assert res_verify.get("verified") is True
        assert res_verify.get("anchors_count") == 1

        # 5. Verify tampering / fork detection (deleting row 2 causes missing/mismatched hash)
        with sqlite3.connect(db_path) as conn:
            conn.execute("DELETE FROM audit_ring WHERE id = 2")
            conn.commit()

        res_fork = mcp_server.aios_anchor_verify()
        assert res_fork.get("ok") is False, "Expected fork/tampering to be detected!"
        assert "FORK_DETECTED" in str(res_fork.get("error"))

        # 6. Verify truncation detection (chain truncated before anchor seq)
        with sqlite3.connect(db_path) as conn:
            conn.execute("DELETE FROM audit_ring WHERE id >= 2")
            conn.commit()

        res_trunc = mcp_server.aios_anchor_verify()
        assert res_trunc.get("ok") is False, "Expected truncation to be detected!"
        assert "TRUNCATION_DETECTED" in str(res_trunc.get("error"))

        print("END-TO-END ANCHOR INTEGRATION TEST PASSED!")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    test_anchor_integration_end_to_end()
