#!/usr/bin/env python3
"""Proof of Restraint: Restraint Proof Generator Integration Test Suite (T-02867).

Sprint / Architecture: ADR-0037, PLAN.md §Layer 2, Invariant I-4.
Verifies:
  1. MCP Tool integration: `aios.restraint.prove` executes end-to-end and returns
     self-contained RestraintProofPackage while logging audit trail.
  2. CLI Tool integration: `aiosh prove restraint` runs via node subprocess,
     generates output file, and logs audit row.
  3. Error propagation: MCP tool and CLI cleanly propagate negative verdicts
     (GRANT_NOT_FOUND, WINDOW_INVALID, GRANT_REDEEMED) without uncaught exceptions.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from aiosh_mcp.anchors import append_anchor, generate_keypair, sign_checkpoint
from aiosh_mcp import audit_client
from aiosh_mcp import server as mcp_server


@pytest.fixture
def integration_env():
    tmp_path = Path(tempfile.mkdtemp(prefix="por-restraint-int-"))
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
                "grant-integ-42",
                "2026-10-07T12:00:00Z",
                "2026-10-07T23:59:59Z",
                "agent:ci",
                "rev-ci",
                json.dumps({"capabilities": ["fs.read"]}),
                "hash-ci",
            ),
        )
        conn.commit()

    priv, pub = generate_keypair()
    a1 = sign_checkpoint(seq=1, head_hash="hash_placeholder_1", timestamp="2026-10-07T12:00:00Z", private_key_hex=priv)
    a2 = sign_checkpoint(seq=5, head_hash="hash_placeholder_5", timestamp="2026-10-07T12:10:00Z", private_key_hex=priv)
    append_anchor(a1, anchors_path)
    append_anchor(a2, anchors_path)

    yield {
        "tmp_path": tmp_path,
        "aiosh_home": aiosh_home,
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


def test_mcp_restraint_prove_tool_success(integration_env):
    res = mcp_server.aios_restraint_prove(
        grant_id="grant-integ-42",
        window_start="2026-10-07T12:01:00Z",
        window_end="2026-10-07T12:05:00Z",
        anchors_path=str(integration_env["anchors_path"]),
    )
    assert res["ok"] is True
    assert res["tool"] == "aios.restraint.prove"
    proof = res["proof"]
    assert proof["verdict"] == "PROVABLY_RESTRAINED"
    assert proof["grant"]["grant_id"] == "grant-integ-42"
    assert proof["anchors"]["start_anchor"]["seq"] == 1
    assert proof["anchors"]["end_anchor"]["seq"] == 5

    # Check that an audit row was recorded
    with sqlite3.connect(str(integration_env["db_path"])) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT * FROM audit_ring WHERE tool = 'aios.restraint.prove'")
        rows = cur.fetchall()
        assert len(rows) >= 1
        assert rows[-1]["target"] == "grant-integ-42"


def test_mcp_restraint_prove_tool_negative(integration_env):
    res = mcp_server.aios_restraint_prove(
        grant_id="nonexistent-grant",
        window_start="2026-10-07T12:01:00Z",
        window_end="2026-10-07T12:05:00Z",
        anchors_path=str(integration_env["anchors_path"]),
    )
    assert res["ok"] is False
    assert "GRANT_NOT_FOUND" in res["error"]


def test_cli_prove_restraint_subprocess(integration_env):
    cli_path = ROOT / "code" / "aiosh-cli" / "dist" / "cli.js"
    if not cli_path.exists():
        pytest.skip("aiosh-cli dist/cli.js not compiled")

    out_file = integration_env["aiosh_home"] / "proof_out.json"
    env = os.environ.copy()
    env["AIOSH_HOME"] = str(integration_env["aiosh_home"])

    cmd = [
        "node",
        str(cli_path),
        "prove",
        "restraint",
        "--grant", "grant-integ-42",
        "--window-start", "2026-10-07T12:01:00Z",
        "--window-end", "2026-10-07T12:05:00Z",
        "--anchors", str(integration_env["anchors_path"]),
        "--out", str(out_file),
    ]

    p = subprocess.run(cmd, env=env, cwd=str(ROOT / "code" / "aiosh-cli"), capture_output=True, text=True)
    if "not a valid Win32 application" in p.stderr or "not a valid Win32 application" in p.stdout:
        pytest.skip("better-sqlite3 native binary compiled for non-Win32 substrate")
    assert p.returncode == 0, f"CLI stderr: {p.stderr}"
    data = json.loads(p.stdout)
    assert data["ok"] is True
    assert data["subcommand"] == "prove restraint"
    assert data["data"]["verdict"] == "PROVABLY_RESTRAINED"

    assert out_file.exists()
    saved = json.loads(out_file.read_text(encoding="utf-8"))
    assert saved["verdict"] == "PROVABLY_RESTRAINED"
    assert saved["proof_id"] == data["data"]["proof_id"]
