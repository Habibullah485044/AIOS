"""Integration tests for Incident Response Runbooks & RustSec MCP surface (T-02998)."""

import os
import tempfile
import pytest

from aiosh_mcp import audit_client
from aiosh_mcp._dispatch import conn_ctx
from aiosh_mcp.incident_runbook_mcp import (
    execute_runbook_action,
    execute_scan_action,
)
from aiosh_mcp.server import mcp


def test_mcp_server_tool_exposure():
    """Verify tool discovery on the FastMCP server instance."""
    tools = mcp._tool_manager._tools
    assert "aios_runbook" in tools
    assert "aios_scan" in tools

    runbook_tool = tools["aios_runbook"]
    assert "list" in runbook_tool.description
    assert "start" in runbook_tool.description


def test_end_to_end_forensic_containment_pipeline():
    """Simulate end-to-end forensic IOC detection and automated runbook containment."""
    with conn_ctx() as conn:
        initial_audit_count = conn.execute("SELECT count(*) FROM audit_ring").fetchone()[0]

    with tempfile.TemporaryDirectory() as tmpdir:
        # 1. Forensic search for synthetic IOC token
        log_path = os.path.join(tmpdir, "forensic_target.log")
        with open(log_path, "w") as f:
            f.write("# Suspicious synthetic activity\nindicator_signature = AIOS_SYNTHETIC_IOC_MARKER_9988\n")

        scan_res = execute_scan_action(
            action="files",
            target=tmpdir,
            pattern="AIOS_SYNTHETIC_IOC_MARKER",
            max_depth=3,
        )
        assert scan_res["ok"] is True
        assert scan_res["matches_count"] >= 1
        assert "forensic_target.log" in scan_res["matches"][0]["file"]
        scan_audit_id = scan_res["audit_id"]
        assert scan_audit_id > 0

        # 2. Trigger incident response containment runbook
        start_res = execute_runbook_action(
            action="start",
            runbook_id="RB-IR-MALWARE-01",
            incident_id="INC-2026-SYNTHETIC-01",
            parameters={"target_pid": "4096", "target_uid": "1001"},
        )
        assert start_res["ok"] is True
        session_id = start_res["session_id"]
        start_audit_id = start_res["audit_id"]
        assert start_audit_id > scan_audit_id

        # 3. Advance all 3 containment steps
        for step_idx in range(3):
            step_res = execute_runbook_action(action="step", session_id=session_id)
            assert step_res["ok"] is True
            assert step_res["current_step_index"] == step_idx + 1

        # 4. Verify completed session status
        status_res = execute_runbook_action(action="status", session_id=session_id)
        assert status_res["ok"] is True
        assert status_res["session"]["status"] == "completed"
        assert status_res["session"]["steps_completed"] == 3

    # 5. Verify all pipeline operations committed audit records
    with conn_ctx() as conn:
        final_audit_count = conn.execute("SELECT count(*) FROM audit_ring").fetchone()[0]
        # At least 1 scan + 1 start + 3 steps + 1 status = 6 audit records
        assert final_audit_count >= initial_audit_count + 6

        rows = conn.execute(
            "SELECT tool, command, outcome FROM audit_ring WHERE id >= ? ORDER BY id ASC",
            (scan_audit_id,),
        ).fetchall()
        tools_executed = [r[0] for r in rows]
        assert "aios.scan" in tools_executed
        assert "aios.runbook" in tools_executed
