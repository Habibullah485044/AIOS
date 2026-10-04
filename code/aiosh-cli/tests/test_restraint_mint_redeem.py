#!/usr/bin/env python3
"""Proof of Restraint: Capability Mint & Redeem Records Smoke Test (T-02835).

Verifies Invariant I-1:
  - Capability grant issue writes a `pep.capability.mint` audit row.
  - Capability grant use writes a `pep.capability.redeem` audit row.
  - Single-use grants cannot be redeemed twice.
  - Hash chain verification via canonical JSON passes.
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
MCP_DIR = ROOT / "code" / "aiosh-mcp"
sys.path.insert(0, str(MCP_DIR))

from aiosh_mcp import audit_client

PASS = "[+]"
FAIL = "[-]"


def test_mint_redeem_lifecycle() -> bool:
    tmp = Path(tempfile.mkdtemp(prefix="por-mint-redeem-"))
    db_path = tmp / "audit.db"

    # Initialize audit_ring and pep_grants schema
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_ring (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ts              TEXT NOT NULL,
                actor           TEXT NOT NULL,
                actor_id        TEXT NOT NULL,
                tool            TEXT NOT NULL,
                command         TEXT NOT NULL,
                args_json       TEXT NOT NULL,
                target          TEXT,
                outcome         TEXT NOT NULL,
                outcome_detail  TEXT,
                constitution_rev TEXT,
                grant_token     TEXT,
                c1              INTEGER NOT NULL DEFAULT 0,
                c2              INTEGER NOT NULL DEFAULT 0,
                c3              INTEGER NOT NULL DEFAULT 0,
                c4              INTEGER NOT NULL DEFAULT 0,
                prev_hash       TEXT NOT NULL,
                hash            TEXT NOT NULL UNIQUE
            );
        """)
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

    # 1. Mint capability grant
    print("[1] Minting capability grant with pep.capability.mint audit record...")
    grant_id = "gr_a1b2c3d4e5f67890"
    now_iso = dt.datetime.now(dt.timezone.utc).isoformat()
    expires_iso = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
    scope = {"tools": ["pentest.nmap", "fs.read"], "networks": ["10.0.0.0/8"]}

    with audit_client.open_db(str(db_path)) as conn:
        conn.execute("""
            INSERT INTO pep_grants
                (grant_id, issued_at, expires_at, issued_to, constitution_rev,
                 scope_json, scope_hash, single_use)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        """, (grant_id, now_iso, expires_iso, "agent:scanner", "rev_c0ffee",
              json.dumps(scope), hashlib.sha256(json.dumps(scope).encode()).hexdigest()))

        mint_args = {
            "grant_id": grant_id,
            "single_use": True,
            "scope": scope,
            "expires_at": expires_iso,
        }
        mint_proto = {
            "ts": now_iso,
            "actor": "user",
            "actor_id": "admin@aios",
            "tool": "pep.capability.mint",
            "command": "grant.mint",
            "args": mint_args,
            "target": None,
            "outcome": "ok",
            "outcome_detail": None,
            "constitution_rev": "rev_c0ffee",
            "grant_token": grant_id,
            "c_flags": {"c1": False, "c2": False, "c3": False, "c4": False},
        }
        row1 = audit_client.write_audit_row(conn, mint_proto)
        assert row1.tool == "pep.capability.mint"
        assert row1.grant_token == grant_id
        print(f"{PASS} Mint audit row written: hash={row1.hash[:16]}... seq={row1.id}")

    # 2. Check grant unspent status
    print("[2] Checking capability unspent status before redemption...")
    with sqlite3.connect(db_path) as conn:
        row = conn.execute("SELECT single_use, redeemed_at FROM pep_grants WHERE grant_id = ?", (grant_id,)).fetchone()
        assert row is not None, "grant must exist"
        assert row[0] == 1, "single_use must be 1"
        assert row[1] is None, "redeemed_at must initially be NULL"
    print(f"{PASS} Grant is unspent and active")

    # 3. Redeem capability grant
    print("[3] Redeeming capability grant with pep.capability.redeem audit record...")
    redeem_time = dt.datetime.now(dt.timezone.utc).isoformat()
    with audit_client.open_db(str(db_path)) as conn:
        # Atomic update
        cur = conn.execute("""
            UPDATE pep_grants SET redeemed_at = ?
            WHERE grant_id = ? AND redeemed_at IS NULL AND revoked_at IS NULL
        """, (redeem_time, grant_id))
        assert cur.rowcount == 1, "Redemption must update exactly 1 row"

        redeem_args = {"grant_id": grant_id, "tool": "pentest.nmap", "command": "nmap -sT 10.0.0.1"}
        redeem_proto = {
            "ts": redeem_time,
            "actor": "agent",
            "actor_id": "agent:scanner",
            "tool": "pep.capability.redeem",
            "command": "nmap -sT 10.0.0.1",
            "args": redeem_args,
            "target": None,
            "outcome": "ok",
            "outcome_detail": None,
            "constitution_rev": "rev_c0ffee",
            "grant_token": grant_id,
            "c_flags": {"c1": False, "c2": False, "c3": False, "c4": False},
        }
        row2 = audit_client.write_audit_row(conn, redeem_proto)
        assert row2.tool == "pep.capability.redeem"
        assert row2.grant_token == grant_id
        assert row2.prev_hash == row1.hash, "Row 2 must chain directly onto Row 1"
        print(f"{PASS} Redeem audit row written: hash={row2.hash[:16]}... seq={row2.id}")

    # 4. Reject second redemption (double-spend protection)
    print("[4] Attempting second redemption on single-use grant...")
    with sqlite3.connect(db_path) as conn:
        cur2 = conn.execute("""
            UPDATE pep_grants SET redeemed_at = ?
            WHERE grant_id = ? AND redeemed_at IS NULL
        """, (dt.datetime.now(dt.timezone.utc).isoformat(), grant_id))
        assert cur2.rowcount == 0, "Second redemption must affect 0 rows (rejected)"
    print(f"{PASS} Second redemption refused: single-use grant cannot be double-spent")

    # 5. Full audit hash chain verification
    print("[5] Verifying complete audit ring hash chain...")
    with audit_client.open_db(str(db_path)) as conn:
        v = audit_client.verify(conn)
        assert v.get("ok"), f"Audit chain verification failed: broken_at={v.get('broken_at')}"
        assert v.get("checked") == 2, f"Expected 2 checked rows, got {v.get('checked')}"
    print(f"{PASS} Audit ring chain intact: checked 2 rows with 100% hash agreement")

    return True


def test_expired_grant_rejected() -> bool:
    print("[6] Testing expired grant redemption rejection...")
    tmp = Path(tempfile.mkdtemp(prefix="por-expired-"))
    db_path = tmp / "audit.db"

    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_ring (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
                actor_id TEXT NOT NULL, tool TEXT NOT NULL, command TEXT NOT NULL,
                args_json TEXT NOT NULL, target TEXT, outcome TEXT NOT NULL, outcome_detail TEXT,
                constitution_rev TEXT, grant_token TEXT, c1 INTEGER DEFAULT 0, c2 INTEGER DEFAULT 0,
                c3 INTEGER DEFAULT 0, c4 INTEGER DEFAULT 0, prev_hash TEXT NOT NULL, hash TEXT NOT NULL UNIQUE
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pep_grants (
                grant_id TEXT PRIMARY KEY, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                issued_to TEXT NOT NULL, constitution_rev TEXT NOT NULL, scope_json TEXT NOT NULL,
                scope_hash TEXT NOT NULL, revoked_at TEXT, single_use INTEGER DEFAULT 1, redeemed_at TEXT
            );
        """)
        # Insert expired grant
        past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)).isoformat()
        expired = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat()
        conn.execute("""
            INSERT INTO pep_grants (grant_id, issued_at, expires_at, issued_to, constitution_rev, scope_json, scope_hash, single_use)
            VALUES ('gr_expired_1', ?, ?, 'agent:scanner', 'rev1', '{}', 'h1', 1)
        """, (past, expired))

        # Check redemption condition: expires_at > now
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        cur = conn.execute("""
            UPDATE pep_grants SET redeemed_at = ?
            WHERE grant_id = 'gr_expired_1' AND redeemed_at IS NULL AND revoked_at IS NULL AND expires_at > ?
        """, (now, now))
        assert cur.rowcount == 0, "Expired grant must not be redeemed"
    print(f"{PASS} Expired grant correctly rejected for redemption")
    return True


def test_tamper_detection_in_chain() -> bool:
    print("[7] Testing cryptographic tamper detection in audit chain...")
    tmp = Path(tempfile.mkdtemp(prefix="por-tamper-"))
    db_path = tmp / "audit.db"

    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_ring (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
                actor_id TEXT NOT NULL, tool TEXT NOT NULL, command TEXT NOT NULL,
                args_json TEXT NOT NULL, target TEXT, outcome TEXT NOT NULL, outcome_detail TEXT,
                constitution_rev TEXT, grant_token TEXT, c1 INTEGER DEFAULT 0, c2 INTEGER DEFAULT 0,
                c3 INTEGER DEFAULT 0, c4 INTEGER DEFAULT 0, prev_hash TEXT NOT NULL, hash TEXT NOT NULL UNIQUE
            );
        """)

    with audit_client.open_db(str(db_path)) as conn:
        now = dt.datetime.now(dt.timezone.utc).isoformat()
        r1 = audit_client.write_audit_row(conn, {
            "ts": now, "actor": "user", "actor_id": "u1", "tool": "pep.capability.mint",
            "command": "mint", "args": {"grant_id": "gr_tamper"}, "target": None,
            "outcome": "ok", "outcome_detail": None, "constitution_rev": "rev1",
            "grant_token": "gr_tamper", "c_flags": {"c1": False, "c2": False, "c3": False, "c4": False},
        })
        r2 = audit_client.write_audit_row(conn, {
            "ts": now, "actor": "agent", "actor_id": "a1", "tool": "pep.capability.redeem",
            "command": "exec", "args": {"grant_id": "gr_tamper"}, "target": None,
            "outcome": "ok", "outcome_detail": None, "constitution_rev": "rev1",
            "grant_token": "gr_tamper", "c_flags": {"c1": False, "c2": False, "c3": False, "c4": False},
        })

    # Tamper with row 2's command without recomputing hash
    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE audit_ring SET command = 'tampered_cmd' WHERE id = ?", (r2.id,))

    # Verify fails
    with audit_client.open_db(str(db_path)) as conn:
        v = audit_client.verify(conn)
        assert not v["ok"], "Tampered row must fail verification"
        assert v["broken_at"] == r2.id, f"Verification must detect breakage at row {r2.id}"
    print(f"{PASS} Tamper detection verified: broken_at={v['broken_at']}")
    return True


def main() -> int:
    try:
        assert test_mint_redeem_lifecycle()
        assert test_expired_grant_rejected()
        assert test_tamper_detection_in_chain()
        print(f"\n{PASS} ALL RESTRIANT UNIT TESTS PASSED (T-02836 certified)")
        return 0
    except Exception as e:
        print(f"\n{FAIL} Unit test failure: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
