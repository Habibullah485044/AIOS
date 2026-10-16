"""Unit tests for Incident Response Runbooks recovery & validation (T-03057)."""

import json
import os
from pathlib import Path
import tempfile
import pytest

from aiosh_mcp.incident_runbook_recovery import (
    RunbookCatalogStatus,
    RunbookIssueSeverity,
    RunbookIssueType,
    RunbookRecoveryService,
    IRREC_ERR_PATH_TRAVERSAL,
    MAX_QUARANTINE_FILES,
    MAX_RUNBOOK_STATE_SIZE,
)
from aiosh_mcp.incident_runbook_data_model import RunbookCatalogSnapshot


def test_unit_case1_valid_input_catalog_and_backup():
    with tempfile.TemporaryDirectory() as tmp_dir:
        state_file = Path(tmp_dir) / "runbook_state.json"
        canonical = RunbookCatalogSnapshot.canonical_baseline()
        raw = {
            "catalog_version": canonical.catalog_version,
            "runbooks": [
                {
                    "id": r.id,
                    "title": r.title,
                    "category": r.category.value,
                    "severity": r.severity.value,
                    "description": r.description,
                    "tags": r.tags,
                    "steps": [
                        {
                            "id": s.id,
                            "title": s.title,
                            "phase": s.phase.value,
                            "target": s.target.value,
                            "action_template": s.action_template,
                            "automated": s.automated,
                            "requires_confirmation": s.requires_confirmation,
                            "timeout_seconds": s.timeout_seconds,
                        }
                        for s in r.steps
                    ],
                }
                for r in canonical.runbooks
            ],
        }
        state_file.write_text(json.dumps(raw, indent=2), encoding="utf-8")

        # Validation check
        rep = RunbookRecoveryService.validate_state_path(state_file)
        assert rep.status == RunbookCatalogStatus.HEALTHY
        assert rep.total_runbooks == len(canonical.runbooks)
        assert len(rep.issues) == 0

        # Backup creation check
        b_path = RunbookRecoveryService.create_backup(state_file)
        assert b_path.exists()

        # Repair should be noop
        repair_rep = RunbookRecoveryService.repair_runbook_state(state_file)
        assert repair_rep.ok is True
        assert repair_rep.action_taken == "noop"


def test_unit_case2_invalid_input_path_traversal_and_malformed_json():
    # Path traversal check
    rep_trav = RunbookRecoveryService.validate_state_path("../../etc/shadow")
    assert rep_trav.status == RunbookCatalogStatus.CORRUPTED
    assert any(i.issue_type == RunbookIssueType.INVALID_PATH_TRAVERSAL for i in rep_trav.issues)

    # Malformed JSON check
    rep_malformed = RunbookRecoveryService.validate_runbook_json("{bad-json", "test_path")
    assert rep_malformed.status == RunbookCatalogStatus.CORRUPTED
    assert any(i.issue_type == RunbookIssueType.INVALID_JSON_SYNTAX for i in rep_malformed.issues)

    # Missing runbooks array
    rep_missing_arr = RunbookRecoveryService.validate_runbook_json("{}", "test_path")
    assert rep_missing_arr.status == RunbookCatalogStatus.CORRUPTED
    assert any(i.issue_type == RunbookIssueType.SCHEMA_MISMATCH for i in rep_missing_arr.issues)

    # Duplicate runbook ID check
    dup_json = json.dumps({
        "catalog_version": "1.0",
        "runbooks": [
            {"id": "RB-DUP", "steps": [{"id": "s1"}]},
            {"id": "RB-DUP", "steps": [{"id": "s1"}]},
        ],
    })
    rep_dup = RunbookRecoveryService.validate_runbook_json(dup_json, "test_dup")
    assert rep_dup.status == RunbookCatalogStatus.DEGRADED
    assert any(i.issue_type == RunbookIssueType.DUPLICATE_RUNBOOK_ID for i in rep_dup.issues)


def test_unit_case3_boundary_values_payload_limit_and_rotation():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Oversized payload
        oversized = "x" * (MAX_RUNBOOK_STATE_SIZE + 10)
        rep_over = RunbookRecoveryService.validate_runbook_json(oversized, "test_over")
        assert rep_over.status == RunbookCatalogStatus.CORRUPTED
        assert any(i.issue_type == RunbookIssueType.OVERSIZED_PAYLOAD for i in rep_over.issues)

        # Quarantine pruning
        p_dir = Path(tmp_dir)
        base_name = "test_runbook.json"
        for i in range(15):
            q_file = p_dir / f"{base_name}.corrupt.100.{i}"
            q_file.write_text(f"quarantine {i}")

        pruned = RunbookRecoveryService.prune_old_quarantine_files(p_dir, base_name)
        assert pruned == 5
        remaining = [f for f in os.listdir(p_dir) if f.startswith(f"{base_name}.corrupt.")]
        assert len(remaining) == MAX_QUARANTINE_FILES


def test_unit_case4_primary_failure_mode_corrupted_state_repaired():
    with tempfile.TemporaryDirectory() as tmp_dir:
        state_file = Path(tmp_dir) / "runbook_state.json"
        state_file.write_text("{broken corrupted content!!!")

        rep = RunbookRecoveryService.repair_runbook_state(state_file)
        assert rep.ok is True
        assert rep.action_taken == "canonical_reinitialized"
        assert rep.quarantine_path is not None
        assert Path(rep.quarantine_path).exists()

        check_rep = RunbookRecoveryService.validate_state_path(state_file)
        assert check_rep.status == RunbookCatalogStatus.HEALTHY
        assert check_rep.total_runbooks == 2
