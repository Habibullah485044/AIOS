"""Integration tests for Incident Response Runbooks configuration (T-03008)."""

import os
import tempfile
import pytest

from aiosh_mcp._dispatch import conn_ctx
from aiosh_mcp.incident_runbook_mcp import execute_runbook_action
from aiosh_mcp.server import mcp
from aiosh_mcp.runbook_config import (
    DEFAULT_CATALOG_PATH,
    DEFAULT_MAX_ACTIVE_SESSIONS,
    ENV_RUNBOOK_MAX_SESSIONS,
)


def test_integration_mcp_runbook_config_surface():
    """Verify aios_runbook exposes the config action on the FastMCP server."""
    tools = mcp._tool_manager._tools
    assert "aios_runbook" in tools
    runbook_tool = tools["aios_runbook"]
    assert "config" in runbook_tool.description


def test_integration_runbook_config_action_dispatch_and_audit():
    """Execute runbook.config through authoritative dispatch and verify audit commitment."""
    with conn_ctx() as conn:
        initial_audit_count = conn.execute("SELECT count(*) FROM audit_ring").fetchone()[0]

    res = execute_runbook_action(action="config")
    assert res["ok"] is True
    assert res["action"] == "config"
    cfg_data = res["config"]
    assert cfg_data["catalog_path"] == DEFAULT_CATALOG_PATH
    assert cfg_data["max_active_sessions"] == DEFAULT_MAX_ACTIVE_SESSIONS
    assert cfg_data["sources"]["catalog_path"] == "default"

    audit_id = res.get("audit_id")
    assert audit_id is not None
    assert audit_id > 0

    with conn_ctx() as conn:
        row = conn.execute(
            "SELECT tool, command, outcome FROM audit_ring WHERE id = ?",
            (audit_id,),
        ).fetchone()
        assert row is not None
        assert row[0] == "aios.runbook"
        assert row[1] == "runbook.config"
        assert row[2] == "ok"


def test_integration_dynamic_session_capping_via_env():
    """Verify that setting AIOSH_RUNBOOK_MAX_SESSIONS dynamically caps session store."""
    old_env = os.environ.get(ENV_RUNBOOK_MAX_SESSIONS)
    try:
        os.environ[ENV_RUNBOOK_MAX_SESSIONS] = "3"

        # Verify config resolution picks up env
        res = execute_runbook_action(action="config")
        assert res["ok"] is True
        assert res["config"]["max_active_sessions"] == 3
        assert res["config"]["sources"]["max_active_sessions"] == "env"

        # Start 4 sessions and verify oldest session is pruned
        s_ids = []
        for i in range(4):
            start_res = execute_runbook_action(
                action="start",
                runbook_id="RB-IR-MALWARE-01",
                incident_id=f"INC-2026-CAP-{i}",
                parameters={"target_pid": "1000", "target_uid": "1000"},
            )
            assert start_res["ok"] is True
            s_ids.append(start_res["session_id"])

        # The first session (s_ids[0]) should have been evicted
        status_old = execute_runbook_action(action="status", session_id=s_ids[0])
        assert status_old["ok"] is False

        # The newest session (s_ids[3]) must exist
        status_new = execute_runbook_action(action="status", session_id=s_ids[3])
        assert status_new["ok"] is True
    finally:
        if old_env is None:
            os.environ.pop(ENV_RUNBOOK_MAX_SESSIONS, None)
        else:
            os.environ[ENV_RUNBOOK_MAX_SESSIONS] = old_env
