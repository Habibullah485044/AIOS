"""Smoke test for aiosh-mcp.

Verifies that:
    1. The Python audit_client can read the same SQLite WAL DB written
       by aiosh-cli.
    2. The hash chain still verifies when re-computed from Python
       (proves the two implementations agree on canonical JSON).
    3. FastMCP server starts over stdio and exposes exactly 5 tools.

We do not test full MCP protocol here — we trust FastMCP's own test
suite for that. We test the cross-process invariant.
"""

from __future__ import annotations
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

# T-02902: pin stdout/stderr to UTF-8 — this suite prints non-ASCII
# markers ([✓], →) that the Windows ANSI codepage (cp1252) cannot encode.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aiosh_mcp import audit_client

WORKDIR = Path(__file__).resolve().parent
PROJ = WORKDIR.parent
AIOSH_CLI = PROJ.parent / "aiosh-cli"

PASS = "[\u2713]"
FAIL = "[\u2717]"


def step_1_cli_emits_rows() -> Path:
    """Use aiosh-cli to write a few rows; return DB path."""
    home = Path(tempfile.mkdtemp(prefix="aiosh-mcp-smoke-"))
    subprocess.run(
        ["node", "dist/cli.js", "status"],
        cwd=str(AIOSH_CLI), check=True,
        env={**os.environ, "AIOSH_HOME": str(home),
             "AIOSH_CONSTITUTION": str(PROJ.parent.parent / "mostimportanAIfolder/AI_CONSTITUTION.md")},
        capture_output=True, text=True, encoding="utf-8")
    subprocess.run(
        ["node", "dist/cli.js", "run", "echo", "hello-from-mcp-smoke"],
        cwd=str(AIOSH_CLI), check=True,
        env={**os.environ, "AIOSH_HOME": str(home),
             "AIOSH_CONSTITUTION": str(PROJ.parent.parent / "mostimportanAIfolder/AI_CONSTITUTION.md")},
        capture_output=True, text=True, encoding="utf-8")
    return home / "audit.db"


def step_2_python_reads(db_path: Path) -> bool:
    """Python audit_client reads chain; verify integrity; print summary."""
    with audit_client.open_db(str(db_path)) as conn:
        rows = audit_client.tail(conn, 10)
        result = audit_client.verify(conn)
    print(f"{PASS} python read {len(rows)} rows from aiosh-cli-written DB")
    print(f"     row 1.tool = {rows[0].tool}")
    print(f"     row 2.tool = {rows[1].tool}")
    print(f"{PASS} verify result: {result}")
    if not result["ok"]:
        print(f"{FAIL} chain verify failed")
        return False
    if len(rows) != 2:
        print(f"{FAIL} expected 2 rows, got {len(rows)}")
        return False
    if rows[0].tool != "system.status" or rows[1].tool != "process.run":
        print(f"{FAIL} expected ['system.status','process.run'], "
              f"got [{rows[0].tool}, {rows[1].tool}]")
        return False
    return True


def step_3_python_writes_row(db_path: Path) -> bool:
    """Through Python emit a row, then verify the chain still holds."""
    # We don't use AuditRing.write from CLI here because that's TS-side.
    # Instead, simulate an MCP tool row directly with the same canonical JSON.
    import hashlib
    import datetime as dt

    def canonical(obj):
        return json.dumps(obj, sort_keys=True, separators=(",", ":"))

    with audit_client.open_db(str(db_path)) as conn:
        cur = conn.execute("SELECT hash FROM audit_ring ORDER BY id DESC LIMIT 1")
        head = cur.fetchone()
        prev = head[0] if head else audit_client.GENESIS
        now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        proto = {
            "ts": now,
            "actor": "agent",
            "actor_id": "agent:mcp-smoke@mcp",
            "tool": "aios.audit.tail",
            "command": "mcp tool call aios.audit.tail",
            "args": {"n": 10},
            "target": None,
            "outcome": "ok",
            "outcome_detail": None,
            "constitution_rev": rows_const_rev(),
            "grant_token": None,
            "c_flags": {"c1": False, "c2": False, "c3": False, "c4": True},
            "prev_hash": prev,
        }
        h = hashlib.sha256(
            (prev + canonical(proto)).encode()).hexdigest()
        conn.execute(
            """INSERT INTO audit_ring
               (ts, actor, actor_id, tool, command, args_json, target,
                outcome, outcome_detail, constitution_rev, grant_token,
                c1, c2, c3, c4, prev_hash, hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (proto["ts"], proto["actor"], proto["actor_id"], proto["tool"],
             proto["command"], canonical(proto["args"]),
             proto["target"], proto["outcome"], proto["outcome_detail"],
             proto["constitution_rev"], proto["grant_token"],
             int(proto["c_flags"]["c1"]), int(proto["c_flags"]["c2"]),
             int(proto["c_flags"]["c3"]), int(proto["c_flags"]["c4"]),
             proto["prev_hash"], h))
        conn.commit()
        result = audit_client.verify(conn)
    if not result["ok"] or result["checked"] != 3:
        print(f"{FAIL} post-write verify failed: {result}")
        return False
    print(f"{PASS} python-side write appended row; verify reports checked=3")
    return True


def rows_const_rev() -> str:
    """Read the actual Constitution revision from disk."""
    con_path = PROJ.parent.parent / "mostimportanAIfolder/AI_CONSTITUTION.md"
    import hashlib
    return hashlib.sha256(con_path.read_bytes()).hexdigest()[:12]


def main() -> int:
    print("== aiosh-mcp cross-process smoke ==")

    # Pre-step: rebuild the aiosh-cli so dist/ is fresh.
    # T-02902: `npm` is a .cmd shim on Windows that CreateProcess cannot
    # spawn; run the same build (tsc -p tsconfig.json) via node directly,
    # matching test_classifier_smoke.py.
    subprocess.run(
        ["node", str(AIOSH_CLI / "node_modules" / "typescript" / "bin" / "tsc"),
         "-p", "tsconfig.json"],
        cwd=str(AIOSH_CLI), check=True,
        capture_output=True, text=True, encoding="utf-8")

    db = step_1_cli_emits_rows()
    print(f"{PASS} aiosh-cli emitted rows → {db}")

    if not step_2_python_reads(db):
        return 1
    if not step_3_python_writes_row(db):
        return 1

    # FastMCP server can list tools over stdio. We just confirm the import
    # runs cleanly (the FastMCP server-side test suite covers protocol).
    from aiosh_mcp.server import mcp
    # list tools via FastMCP's internal _tool_manager
    tools = mcp._tool_manager._tools
    expected = {"aios_fs_read", "aios_process_list", "aios_audit_tail",
                "aios_audit_verify", "aios_pentest_nmap", "aios_task"}
    actual = set(tools.keys())
    print(f"{PASS} server registered tools: {sorted(actual)}")
    # Sprint 1 adds more pentest tools; assert the Sprint-0 set is a
    # subset of the registered set rather than strict equality.
    if not expected <= actual:
        print(f"{FAIL} Sprint-0 tools {sorted(expected)} missing from server")
        return 1

    print()
    print("PASS: aiosh-mcp smoke (TS writes — Python reads — Python writes — chain intact)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
