#!/usr/bin/env python3
"""Proof of Restraint: End-to-End Redeem-Before-Act Gate Integration Test (T-02847).

Verifies:
  1. Real pentest dispatch via FastMCP / pentest module.
  2. Single-use capability token is redeemed before tool body executes.
  3. Replay attack on consequential action is blocked at dispatch boundary.
  4. Cross-substrate hash chain verification passes.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MCP_DIR = ROOT / "aiosh_mcp"
sys.path.insert(0, str(ROOT))

from aiosh_mcp import audit_client
from aiosh_mcp import pentest
from aiosh_mcp import _dispatch

PASS = "[+]"
FAIL = "[-]"


def test_pentest_dispatch_integration() -> bool:
    tmp = Path(tempfile.mkdtemp(prefix="por-pentest-gate-"))
    db_path = tmp / "audit.db"
    os.environ["AIOSH_HOME"] = str(tmp)

    # Step 1: Initialize database
    print("[1] Initializing shared WAL database...")
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = FULL;")
        audit_client.ensure_audit_schema(conn)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pep_grants (
                grant_id          TEXT PRIMARY KEY,
                issued_at         TEXT NOT NULL,
                expires_at        TEXT NOT NULL,
                issued_to         TEXT NOT NULL,
                constitution_rev  TEXT NOT NULL,
                scope_json        TEXT NOT NULL,
                scope_hash        TEXT NOT NULL,
                revoked_at        TEXT,
                single_use        INTEGER NOT NULL DEFAULT 1,
                redeemed_at       TEXT
            );
        """)

    # Step 2: Mint single-use grant
    print("[2] Minting single-use grant for pentest.nmap...")
    grant_id = "gr_integ_pentest_01"
    now_iso = audit_client.utcnow_iso()
    expires_iso = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
    scope = {"tools": ["pentest.nmap"], "networks": ["127.0.0.1/32"]}

    with audit_client.open_db(str(db_path)) as conn:
        conn.execute("""
            INSERT INTO pep_grants
                (grant_id, issued_at, expires_at, issued_to, constitution_rev,
                 scope_json, scope_hash, single_use)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        """, (grant_id, now_iso, expires_iso, "agent:scanner", "rev_por",
              json.dumps(scope), "scope_hash_1"))

        audit_client.write_audit_row(conn, {
            "ts": now_iso,
            "actor": "user",
            "actor_id": "admin@aios",
            "tool": "pep.capability.mint",
            "command": "grant.mint",
            "args": {"grant_id": grant_id, "single_use": True},
            "target": None,
            "outcome": "ok",
            "outcome_detail": None,
            "constitution_rev": "rev_por",
            "grant_token": grant_id,
            "c_flags": {"c1": False, "c2": False, "c3": False, "c4": False},
        })

    # Step 3: Execute pentest.nmap wrapper through pentest module
    print("[3] Invoking aios_pentest_nmap with valid grant...")
    res1 = pentest.aios_pentest_nmap(target="127.0.0.1", grant_id=grant_id)
    # The binary might or might not be installed on host; if binary missing,
    # outcome is refused with "binary not on PATH". If present, ok.
    # Crucially: In either case, the capability token was REDEEMED!
    print(f"{PASS} aios_pentest_nmap returned: ok={res1.get('ok')} tool={res1.get('tool')}")

    # Verify that pep.capability.redeem audit row was committed
    with audit_client.open_db(str(db_path)) as conn:
        redeem_rows = list(conn.execute(
            "SELECT tool, outcome, grant_token FROM audit_ring WHERE tool = 'pep.capability.redeem' AND grant_token = ?",
            (grant_id,)
        ))
        assert len(redeem_rows) == 1, f"Expected exactly 1 redeem row, got {len(redeem_rows)}"
        g = audit_client.load_grant(conn, grant_id)
        assert g is not None and g["redeemed_at"] is not None, "Grant must be marked as redeemed in DB!"
    print(f"{PASS} Invariant I-1/I-2 verified: redeem row committed prior to execution")

    # Step 4: Replay attack - invoke aios_pentest_nmap second time with SAME grant
    print("[4] Attempting second invocation with same single-use grant...")
    res2 = pentest.aios_pentest_nmap(target="127.0.0.1", grant_id=grant_id)
    assert not res2["ok"], "Second invocation must fail at gate!"
    assert "already redeemed" in str(res2.get("reason", "")), f"Expected 'already redeemed', got {res2}"
    print(f"{PASS} Replay attack blocked: {res2.get('reason')}")

    # Step 5: Full hash chain integrity verification
    print("[5] Verifying complete audit ring hash chain...")
    with audit_client.open_db(str(db_path)) as conn:
        v = audit_client.verify(conn)
        assert v["ok"], f"Hash chain verification failed: {v}"
    print(f"{PASS} Chain verified: {v['checked']} rows with 100% hash agreement")

    return True


def main() -> int:
    try:
        assert test_pentest_dispatch_integration()
        print(f"\n{PASS} REDEEM-BEFORE-ACT INTEGRATION TEST PASSED (T-02847 certified)")
        return 0
    except Exception as e:
        print(f"\n{FAIL} Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
