#!/usr/bin/env python3
"""Proof of Restraint — milestone demo (T-02892).

Runs PLAN.md §Demo end to end against the real components:

  1. Mint a capability (PEP grant) and leave it unused.
  2. Anchor the audit ring (signed Ed25519 checkpoints).
  3. Generate a restraint proof for the unused grant.
  4. Verify it with the standalone verifier  -> PROVABLY_RESTRAINED.
  5. Tamper: delete a row from the ring and re-chain it, then try again
     -> verification FAILS (HEAD_HASH_MISMATCH).

Usage:
  python3 tools/demo_por.py

Exit code 0 only when the honest proof verifies AND the tampered proof is
rejected (fail-closed demo contract).
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "code" / "aiosh-mcp"))

from aiosh_mcp import anchors as anchors_mod  # noqa: E402
from aiosh_mcp import audit_client, restraint, verifier  # noqa: E402

WINDOW_START = "2026-10-07T12:01:00Z"
WINDOW_END = "2026-10-07T12:05:00Z"
ANCHOR_START_TS = "2026-10-07T12:00:00Z"
ANCHOR_END_TS = "2026-10-07T12:10:00Z"
GRANT_ID = "gr_demo_untouched"


def banner(text: str) -> None:
    print(f"\n=== {text} ===")


def row_proto(ts: str, tool: str, command: str, args: dict,
              target: str | None = None, grant_token: str | None = None) -> dict:
    return {
        "ts": ts, "actor": "user", "actor_id": "demo@aios",
        "tool": tool, "command": command, "args": args,
        "target": target, "outcome": "ok", "outcome_detail": None,
        "constitution_rev": "rev-demo", "grant_token": grant_token,
        "c_flags": {"c1": False, "c2": False, "c3": False, "c4": False},
    }


def mint_capability(conn: sqlite3.Connection, grant_id: str) -> None:
    """I-1 mint contract: one pep_grants row + one pep.capability.mint audit row."""
    scope = {"tools": ["pentest.nmap"], "paths": [], "networks": []}
    conn.execute(
        """INSERT INTO pep_grants (
            grant_id, issued_at, expires_at, issued_to, constitution_rev,
            scope_json, scope_hash, single_use
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (grant_id, "2026-10-07T11:50:00Z", "2026-10-07T23:59:59Z",
         "agent:demo", "rev-demo", json.dumps(scope, sort_keys=True),
         audit_client.sha256_hex(json.dumps(scope, sort_keys=True)), 1),
    )
    audit_client.write_audit_row(conn, row_proto(
        "2026-10-07T12:05:30Z", "pep.capability.mint", "capability.mint",
        {"grant_id": grant_id, "single_use": True, "scope": scope,
         "expires_at": "2026-10-07T23:59:59Z"},
        grant_token=grant_id))


def rechain(conn: sqlite3.Connection) -> int:
    """Recompute prev_hash/hash for every live row in id order (the attacker's
    re-chain after deleting a row). Returns the new tail hash."""
    anchor = audit_client.latest_segment_head(conn) or audit_client.GENESIS
    prev = anchor
    rows = conn.execute("SELECT * FROM audit_ring ORDER BY id ASC").fetchall()
    for raw in rows:
        row = audit_client.AuditRow.from_sql(raw)
        try:
            row = copy.replace(row, prev_hash=prev)
        except TypeError:
            row.prev_hash = prev
        proto = audit_client._hash_proto(row)
        h = audit_client.sha256_hex(prev + audit_client.canonical(proto))
        conn.execute("UPDATE audit_ring SET prev_hash = ?, hash = ? WHERE id = ?",
                     (prev, h, row.id))
        prev = h
    conn.commit()
    return prev


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="por-demo-"))
    home = tmp / ".aios"
    anchors_dir = home / "anchors"
    anchors_dir.mkdir(parents=True)
    db_path = home / "audit.db"
    anchors_path = anchors_dir / "anchors.jsonl"
    os.environ["AIOSH_HOME"] = str(home)

    print("AIOS — Proof of Restraint milestone demo (T-02892)")
    print(f"sandbox: {home}")

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        audit_client.ensure_audit_schema(conn)
        audit_client.ensure_pep_schema(conn)

        banner("STEP 1 — normal activity + one shadow action, then mint a capability (unused)")
        for ts, tool, cmd, args in [
            ("2026-10-07T12:01:00Z", "aios.fs.read", "cat /etc/hosts", {"path": "/etc/hosts"}),
            ("2026-10-07T12:02:00Z", "aios.fs.read", "cat /etc/os-release", {"path": "/etc/os-release"}),
            ("2026-10-07T12:03:00Z", "pentest.nmap", "pentest.nmap 10.0.0.5", {"target": "10.0.0.5"}),
            ("2026-10-07T12:04:00Z", "aios.fs.read", "cat /proc/version", {"path": "/proc/version"}),
            ("2026-10-07T12:05:00Z", "aios.fs.read", "cat /etc/hostname", {"path": "/etc/hostname"}),
        ]:
            audit_client.write_audit_row(conn, row_proto(ts, tool, cmd, args, target=args.get("path") or args.get("target")))
        conn.commit()
        mint_capability(conn, GRANT_ID)
        conn.commit()
        print(f"minted grant {GRANT_ID} (single_use, NEVER redeemed)")
        print("row id 3 is a shadow pentest.nmap action an attacker will later delete")

        banner("STEP 2 — anchor the audit ring (signed Ed25519 checkpoints)")
        first = conn.execute("SELECT id, hash FROM audit_ring ORDER BY id ASC LIMIT 1").fetchone()
        tail = conn.execute("SELECT id, hash FROM audit_ring ORDER BY id DESC LIMIT 1").fetchone()
        priv, pub = anchors_mod.generate_keypair()
        a1 = anchors_mod.sign_checkpoint(seq=first["id"], head_hash=first["hash"],
                                         timestamp=ANCHOR_START_TS, private_key_hex=priv)
        a2 = anchors_mod.sign_checkpoint(seq=tail["id"], head_hash=tail["hash"],
                                         timestamp=ANCHOR_END_TS, private_key_hex=priv)
        anchors_mod.append_anchor(a1, anchors_path)
        anchors_mod.append_anchor(a2, anchors_path)
        print(f"start anchor: seq={a1.seq} ts={a1.timestamp}")
        print(f"end   anchor: seq={a2.seq} ts={a2.timestamp} head_hash={a2.head_hash[:16]}...")

        banner("STEP 3 — generate a restraint proof for the unused grant")
        pkg = restraint.generate_restraint_proof(
            conn=conn, grant_id=GRANT_ID,
            window_start=WINDOW_START, window_end=WINDOW_END,
            anchors_path=str(anchors_path))
        d = pkg.to_dict()
        print(f"proof_id  : {d['proof_id']}")
        print(f"verdict   : {d['verdict']}")
        print(f"grant     : {d['grant']['grant_id']} redeemed_at={d['grant']['redeemed_at']}")
        print(f"live rows : seq {d['live_range']['first_seq']}..{d['live_range']['last_seq']}")

        banner("STEP 4 — verify with the standalone verifier (zero-database)")
        proof_file = tmp / "proof.json"
        proof_file.write_text(json.dumps(d), encoding="utf-8")
        res = verifier.verify_restraint_proof(proof_file, [pub])
        print(f"valid  : {res.valid}")
        print(f"reason : {res.reason}")
        print(f"checks : {json.dumps(res.checks, sort_keys=True)}")
        assert res.valid is True, "honest proof must verify"
        assert all(res.checks.values())

        cli = subprocess.run(
            [sys.executable, "-m", "aiosh_mcp.verifier", str(proof_file),
             "--pubkey", pub],
            cwd=str(REPO / "code" / "aiosh-mcp"), capture_output=True, text=True,
            timeout=60)
        print(f"standalone CLI exit code: {cli.returncode}")
        out1 = (cli.stdout.strip() or cli.stderr.strip()).splitlines()
        print("standalone CLI said:", out1[-1] if out1 else "(no output)")
        assert cli.returncode == 0, "standalone CLI must accept the honest proof"

        banner("STEP 5 — TAMPER: delete the shadow row and re-chain the ring")
        before = audit_client.verify_live(conn)
        print(f"chain check before tamper: {before}")
        conn.execute("DELETE FROM audit_ring WHERE id = 3")
        conn.commit()
        new_tail = rechain(conn)
        after = audit_client.verify_live(conn)
        print(f"deleted row id 3 and re-chained all hashes")
        print(f"chain check after tamper : {after}  <- internally consistent again")
        print(f"new tail hash            : {new_tail[:16]}...")
        print(f"signed anchor head_hash  : {a2.head_hash[:16]}...  <- STILL the old value")

        banner("STEP 5b — the attacker presents a freshly generated proof")
        forged = restraint.generate_restraint_proof(
            conn=conn, grant_id=GRANT_ID,
            window_start=WINDOW_START, window_end=WINDOW_END,
            anchors_path=str(anchors_path)).to_dict()
        forged_file = tmp / "proof_tampered.json"
        forged_file.write_text(json.dumps(forged), encoding="utf-8")
        res2 = verifier.verify_restraint_proof(forged_file, [pub])
        print(f"valid  : {res2.valid}")
        print(f"reason : {res2.reason}")
        print(f"checks : {json.dumps(res2.checks, sort_keys=True)}")
        assert res2.valid is False, "tampered proof must NOT verify"
        assert "HEAD_HASH_MISMATCH" in (res2.reason or "")

        cli2 = subprocess.run(
            [sys.executable, "-m", "aiosh_mcp.verifier", str(forged_file),
             "--pubkey", pub],
            cwd=str(REPO / "code" / "aiosh-mcp"), capture_output=True, text=True,
            timeout=60)
        print(f"standalone CLI exit code: {cli2.returncode} (must be non-zero)")
        out2 = (cli2.stdout.strip() or cli2.stderr.strip()).splitlines()
        print("standalone CLI said:", out2[-1] if out2 else "(no output)")
        assert cli2.returncode != 0

        banner("DEMO RESULT")
        print("PASS: unused grant proved PROVABLY_RESTRAINED; post-anchor tamper (delete + re-chain) REJECTED.")
        print("Note: the original proof still verifies — it attests to the pre-tamper state;")
        print("      what the tamper destroys is the attacker's ability to mint NEW valid proofs.")
        return 0
    finally:
        conn.close()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
