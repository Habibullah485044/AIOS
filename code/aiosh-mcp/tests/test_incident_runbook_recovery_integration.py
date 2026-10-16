"""Integration tests for Incident Response Runbooks recovery & validation (T-03058)."""

from pathlib import Path
import tempfile
import pytest

from aiosh_mcp.incident_runbook_mcp import execute_runbook_action


def test_integration_recovery_fastmcp_lifecycle():
    with tempfile.TemporaryDirectory() as tmp_dir:
        state_file = Path(tmp_dir) / "runbook_state.json"

        # 1. recovery_check on non-existent file
        res_check = execute_runbook_action(
            action="recovery_check",
            parameters={"path": str(state_file)},
        )
        assert res_check["action"] == "recovery_check"
        assert res_check["ok"] is False
        assert res_check["report"]["status"] == "missing"
        assert "audit_id" in res_check

        # 2. recovery_repair -> creates baseline
        res_repair1 = execute_runbook_action(
            action="recovery_repair",
            parameters={"path": str(state_file)},
        )
        assert res_repair1["ok"] is True
        assert res_repair1["action"] == "recovery_repair"
        assert res_repair1["report"]["action_taken"] == "canonical_reinitialized"
        assert "audit_id" in res_repair1
        assert state_file.exists()

        # 3. recovery_check on repaired state -> healthy
        res_check_healthy = execute_runbook_action(
            action="recovery_check",
            parameters={"path": str(state_file)},
        )
        assert res_check_healthy["ok"] is True
        assert res_check_healthy["report"]["status"] == "healthy"
        assert res_check_healthy["report"]["total_runbooks"] == 2

        # 4. recovery_snapshot -> creates .bak
        res_snap = execute_runbook_action(
            action="recovery_snapshot",
            parameters={"path": str(state_file)},
        )
        assert res_snap["ok"] is True
        assert res_snap["action"] == "recovery_snapshot"
        assert Path(res_snap["backup_path"]).exists()
        assert "audit_id" in res_snap

        # 5. Corrupt file and recovery_repair -> restores from backup
        state_file.write_text("corrupted content!!!", encoding="utf-8")
        res_repair2 = execute_runbook_action(
            action="recovery_repair",
            parameters={"path": str(state_file)},
        )
        assert res_repair2["ok"] is True
        assert res_repair2["report"]["action_taken"] == "backup_restored"
        assert res_repair2["report"]["quarantine_path"] is not None
        assert Path(res_repair2["report"]["quarantine_path"]).exists()

        # 6. Final check is healthy
        res_check_final = execute_runbook_action(
            action="recovery_check",
            parameters={"path": str(state_file)},
        )
        assert res_check_final["ok"] is True
        assert res_check_final["report"]["status"] == "healthy"
