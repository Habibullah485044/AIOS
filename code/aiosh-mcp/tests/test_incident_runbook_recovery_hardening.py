"""Hardening tests for Incident Response Runbooks recovery & validation (T-03060)."""

from pathlib import Path
import tempfile
import pytest

from aiosh_mcp.incident_runbook_recovery import (
    RunbookCatalogStatus,
    RunbookRecoveryResultEnvelope,
    RunbookRecoveryService,
    IRREC_ERR_IO,
    IRREC_ERR_VALIDATION,
)
from aiosh_mcp.incident_runbook_mcp import execute_runbook_action


def test_recovery_envelope_types_and_serialization():
    env_ok = RunbookRecoveryResultEnvelope.success({"status": "ok"})
    assert env_ok.ok is True
    assert env_ok.audit_row_required is False
    d_ok = env_ok.to_dict()
    assert d_ok["ok"] is True

    env_err = RunbookRecoveryResultEnvelope.failure("ERR_CODE", "Something failed")
    assert env_err.ok is False
    assert env_err.audit_row_required is True
    d_err = env_err.to_dict()
    assert d_err["ok"] is False
    assert d_err["audit_row_required"] is True


def test_safe_wrappers_hardening():
    with tempfile.TemporaryDirectory() as tmp_dir:
        p_dir = Path(tmp_dir)
        state_file = p_dir / "runbook_state.json"

        # 1. validate_state_path_safe on missing
        env_miss = RunbookRecoveryService.validate_state_path_safe(state_file)
        assert env_miss.ok is False
        assert env_miss.audit_row_required is True
        assert env_miss.data.status == RunbookCatalogStatus.MISSING

        # 2. repair_runbook_state_safe
        env_rep = RunbookRecoveryService.repair_runbook_state_safe(state_file)
        assert env_rep.ok is True
        assert env_rep.data.action_taken == "canonical_reinitialized"

        # 3. validate_state_path_safe on healthy
        env_healthy = RunbookRecoveryService.validate_state_path_safe(state_file)
        assert env_healthy.ok is True
        assert env_healthy.audit_row_required is False

        # 4. create_backup_safe on non-existent file
        missing_file = p_dir / "does_not_exist.json"
        env_b_err = RunbookRecoveryService.create_backup_safe(missing_file)
        assert env_b_err.ok is False
        assert env_b_err.audit_row_required is True

        # 5. restore_snapshot_safe with corrupted snapshot
        bad_snap = p_dir / "bad.snap"
        bad_snap.write_text("{broken json")
        env_restore_err = RunbookRecoveryService.restore_snapshot_safe(bad_snap, state_file)
        assert env_restore_err.ok is False
        assert env_restore_err.audit_row_required is True

        # 6. Verify zero lingering .tmp files
        tmp_files = [f for f in p_dir.iterdir() if ".tmp." in f.name]
        assert len(tmp_files) == 0


def test_fastmcp_hardening_audit_gates():
    with tempfile.TemporaryDirectory() as tmp_dir:
        missing_file = Path(tmp_dir) / "missing.json"

        # recovery_snapshot on missing file yields ok=False with honest audit row
        res_snap_err = execute_runbook_action(
            action="recovery_snapshot",
            parameters={"path": str(missing_file)},
        )
        assert res_snap_err["ok"] is False
        assert "audit_id" in res_snap_err
        assert res_snap_err["audit_row_required"] is True
