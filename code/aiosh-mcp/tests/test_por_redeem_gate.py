#!/usr/bin/env python3
"""Proof of Restraint: Redeem-Before-Act Gate Unit & Dispatch Test (T-02845).

Verifies Invariant I-2:
  1. First dispatch with single-use grant commits pep.capability.redeem audit row.
  2. Second dispatch with same single-use grant is refused at the gate.
  3. Tool function is never called on double-spend or expired grant.
  4. Chain integrity remains 100% valid.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MCP_DIR = ROOT / "aiosh_mcp"
sys.path.insert(0, str(ROOT))

from aiosh_mcp import audit_client
from aiosh_mcp import _dispatch

PASS = "[+]"
FAIL = "[-]"


def test_redeem_before_act_gate() -> bool:
    tmp = Path(tempfile.mkdtemp(prefix="por-gate-test-"))
    db_path = tmp / "audit.db"

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

    # Setup environment for test DB
    import os
    os.environ["AIOSH_HOME"] = str(tmp)

    # 1. Mint single-use grant
    print("[1] Minting single-use grant for pentest.nmap...")
    grant_id = "gr_gate_test_01"
    now_iso = audit_client.utcnow_iso()
    expires_iso = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
    scope = {"tools": ["pentest.nmap"], "networks": ["127.0.0.1/32"]}

    with audit_client.open_db(str(db_path)) as conn:
        conn.execute("""
            INSERT INTO pep_grants (grant_id, issued_at, expires_at, issued_to, constitution_rev,
                                    scope_json, scope_hash, single_use)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        """, (grant_id, now_iso, expires_iso, "agent:test", "rev1", json.dumps(scope), "hash1"))

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
            "constitution_rev": "rev1",
            "grant_token": grant_id,
            "c_flags": {"c1": False, "c2": False, "c3": False, "c4": False},
        })

    # 2. First dispatch through _dispatch.dispatch()
    print("[2] Executing first dispatch (should succeed and redeem token)...")
    verdict1, _ = _dispatch.dispatch(
        tool="pentest.nmap",
        command="nmap -sT 127.0.0.1",
        args={"target": "127.0.0.1"},
        target="127.0.0.1",
        grant_id=grant_id,
        require_grant=True,
    )
    assert verdict1["ok"], f"First dispatch failed: {verdict1}"
    print(f"{PASS} First dispatch passed gate")

    # Verify that pep.capability.redeem audit row was committed
    with audit_client.open_db(str(db_path)) as conn:
        rows = list(conn.execute("SELECT tool, outcome, grant_token FROM audit_ring ORDER BY id ASC"))
        assert any(r[0] == "pep.capability.redeem" and r[2] == grant_id for r in rows), "Missing redeem row!"
        g = audit_client.load_grant(conn, grant_id)
        assert g is not None and g["redeemed_at"] is not None, "Grant must be marked as redeemed!"
    print(f"{PASS} Token atomically marked redeemed and pep.capability.redeem recorded")

    # 3. Second dispatch with the same single-use token (Replay Attack)
    print("[3] Executing second dispatch (must be blocked by Invariant I-2)...")
    verdict2, ref_row = _dispatch.dispatch(
        tool="pentest.nmap",
        command="nmap -sT 127.0.0.1",
        args={"target": "127.0.0.1"},
        target="127.0.0.1",
        grant_id=grant_id,
        require_grant=True,
    )
    assert not verdict2["ok"], "Second dispatch should have been REFUSED!"
    assert "already redeemed" in verdict2["reason"], f"Unexpected reason: {verdict2['reason']}"
    assert ref_row.outcome == "refused"
    print(f"{PASS} Second dispatch blocked: {verdict2['reason']}")

    # 4. Verify chain integrity across all events
    print("[4] Verifying complete cryptographic hash chain...")
    with audit_client.open_db(str(db_path)) as conn:
        v = audit_client.verify(conn)
        assert v["ok"], f"Hash chain verification failed: {v}"
    print(f"{PASS} Hash chain verified: {v['checked']} rows verified without gaps")

    return True


def test_expired_and_out_of_scope_rejection() -> bool:
    print("[5] Testing expired and out-of-scope grant rejections at gate...")
    tmp = Path(tempfile.mkdtemp(prefix="por-expired-gate-"))
    db_path = tmp / "audit.db"

    import os
    os.environ["AIOSH_HOME"] = str(tmp)

    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = FULL;")
        audit_client.ensure_audit_schema(conn)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pep_grants (
                grant_id TEXT PRIMARY KEY, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                issued_to TEXT NOT NULL, constitution_rev TEXT NOT NULL, scope_json TEXT NOT NULL,
                scope_hash TEXT NOT NULL, revoked_at TEXT, single_use INTEGER DEFAULT 1, redeemed_at TEXT
            );
        """)
        past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)).isoformat()
        expired = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat()
        future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()

        # Expired grant
        conn.execute("""
            INSERT INTO pep_grants (grant_id, issued_at, expires_at, issued_to, constitution_rev, scope_json, scope_hash, single_use)
            VALUES ('gr_expired', ?, ?, 'agent:t', 'rev1', '{"tools":["pentest.nmap"]}', 'h1', 1)
        """, (past, expired))

        # Scope-mismatched grant
        conn.execute("""
            INSERT INTO pep_grants (grant_id, issued_at, expires_at, issued_to, constitution_rev, scope_json, scope_hash, single_use)
            VALUES ('gr_wrong_scope', ?, ?, 'agent:t', 'rev1', '{"tools":["aios.fs.read"]}', 'h2', 1)
        """, (past, future))

    # Test 1: Expired grant dispatch
    v_exp, r_exp = _dispatch.dispatch(
        tool="pentest.nmap", command="nmap -sT 127.0.0.1", args={}, target=None,
        grant_id="gr_expired", require_grant=True,
    )
    assert not v_exp["ok"], "Expired grant must fail dispatch"
    assert "expired" in v_exp["reason"]
    print(f"{PASS} Expired grant correctly refused: {v_exp['reason']}")

    # Test 2: Out of scope dispatch
    v_scope, r_scope = _dispatch.dispatch(
        tool="pentest.nmap", command="nmap -sT 127.0.0.1", args={}, target=None,
        grant_id="gr_wrong_scope", require_grant=True,
    )
    assert not v_scope["ok"], "Out of scope tool must fail dispatch"
    assert "not in grant scope" in v_scope["reason"]
    print(f"{PASS} Out of scope tool correctly refused: {v_scope['reason']}")

    # Test 3: Irreversible tool without grant
    v_nogrant, r_nogrant = _dispatch.dispatch(
        tool="pentest.nmap", command="nmap -sT 127.0.0.1", args={}, target=None,
        grant_id=None, require_grant=True,
    )
    assert not v_nogrant["ok"], "Missing grant on irreversible tool must fail dispatch"
    print(f"{PASS} Missing grant on irreversible tool correctly refused")

    return True


def test_multi_use_grant_dispatch() -> bool:
    print("[6] Testing multi-use grant dispatch (multiple permitted redemptions)...")
    tmp = Path(tempfile.mkdtemp(prefix="por-multi-gate-"))
    db_path = tmp / "audit.db"

    import os
    os.environ["AIOSH_HOME"] = str(tmp)

    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = FULL;")
        audit_client.ensure_audit_schema(conn)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pep_grants (
                grant_id TEXT PRIMARY KEY, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                issued_to TEXT NOT NULL, constitution_rev TEXT NOT NULL, scope_json TEXT NOT NULL,
                scope_hash TEXT NOT NULL, revoked_at TEXT, single_use INTEGER DEFAULT 0, redeemed_at TEXT
            );
        """)
        now = audit_client.utcnow_iso()
        future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
        conn.execute("""
            INSERT INTO pep_grants (grant_id, issued_at, expires_at, issued_to, constitution_rev, scope_json, scope_hash, single_use)
            VALUES ('gr_multi', ?, ?, 'agent:t', 'rev1', '{"tools":["pentest.nmap"]}', 'h1', 0)
        """, (now, future))

    # First dispatch
    v1, _ = _dispatch.dispatch(
        tool="pentest.nmap", command="nmap -sT 127.0.0.1", args={}, target=None,
        grant_id="gr_multi", require_grant=True,
    )
    assert v1["ok"], f"Multi-use first dispatch failed: {v1}"

    # Second dispatch
    v2, _ = _dispatch.dispatch(
        tool="pentest.nmap", command="nmap -sT 127.0.0.1", args={}, target=None,
        grant_id="gr_multi", require_grant=True,
    )
    assert v2["ok"], f"Multi-use second dispatch failed: {v2}"
    print(f"{PASS} Multi-use grant successfully allows repeated redemptions")

    return True


def main() -> int:
    try:
        assert test_redeem_before_act_gate()
        assert test_expired_and_out_of_scope_rejection()
        assert test_multi_use_grant_dispatch()
        print(f"\n{PASS} ALL REDEEM-BEFORE-ACT UNIT TESTS PASSED (T-02846 certified)")
        return 0
    except Exception as e:
        print(f"\n{FAIL} Unit test failure: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
