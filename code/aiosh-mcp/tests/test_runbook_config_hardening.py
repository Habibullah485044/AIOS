"""Hardening tests for Incident Response Runbooks configuration (T-03010)."""

import os
import tempfile
import pytest

from aiosh_mcp._dispatch import conn_ctx
from aiosh_mcp.incident_runbook_mcp import execute_runbook_action
from aiosh_mcp.runbook_config import (
    DEFAULT_CATALOG_PATH,
    RUNBOOKCONF_ERR_FILE_SIZE,
    RUNBOOKCONF_ERR_PATH_TRAVERSAL,
    MAX_CONFIG_FILE_BYTES,
    safe_resolve_runbook_config,
)


def test_safe_resolve_runbook_config_success():
    res = safe_resolve_runbook_config()
    assert res["ok"] is True
    assert res["config"]["catalog_path"] == DEFAULT_CATALOG_PATH


def test_safe_resolve_runbook_config_failure_envelope():
    # Pass path traversal; safe wrapper must return ok=False instead of raising
    res = safe_resolve_runbook_config(config_path="../traversal/evil.json")
    assert res["ok"] is False
    assert res["error_code"] == RUNBOOKCONF_ERR_PATH_TRAVERSAL
    assert "strictly prohibited" in res["error"]
    assert res["config"]["catalog_path"] == DEFAULT_CATALOG_PATH


def test_mcp_config_failure_emits_honest_audit_row():
    """Verify that a failed config request produces an honest audit row per ADR-0035 §F-2."""
    with conn_ctx() as conn:
        initial_audit_count = conn.execute("SELECT count(*) FROM audit_ring").fetchone()[0]

    # Call with path traversal to force failure
    res = execute_runbook_action(
        action="config",
        parameters={"config_path": "../evil/traversal.json"},
    )
    assert res["ok"] is False
    assert res["action"] == "config"
    assert RUNBOOKCONF_ERR_PATH_TRAVERSAL in res["error"]
    audit_id = res.get("audit_id")
    assert audit_id is not None
    assert audit_id > 0

    with conn_ctx() as conn:
        row = conn.execute(
            "SELECT tool, command, outcome, outcome_detail FROM audit_ring WHERE id = ?",
            (audit_id,),
        ).fetchone()
        assert row is not None
        assert row[0] == "aios.runbook"
        assert row[1] == "runbook.config"
        assert row[2] == "error"
        assert RUNBOOKCONF_ERR_PATH_TRAVERSAL in row[3]


def test_cleanup_on_oversized_config_file():
    """Ensure file descriptor is cleaned up and error envelope returned on oversized file."""
    with tempfile.TemporaryDirectory() as td:
        huge_file = os.path.join(td, "huge.json")
        with open(huge_file, "wb") as f:
            f.write(b"X" * (MAX_CONFIG_FILE_BYTES + 50))

        res = safe_resolve_runbook_config(config_path=huge_file)
        assert res["ok"] is False
        assert res["error_code"] == RUNBOOKCONF_ERR_FILE_SIZE
        assert "limit" in res["error"]
