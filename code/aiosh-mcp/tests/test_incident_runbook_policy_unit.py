"""Focused unit tests for Incident Response Runbooks Security Policy in Python (T-03027)."""

import tempfile
from pathlib import Path
import pytest

from aiosh_mcp.incident_runbook_data_model import (
    IncidentCategory,
    RunbookCatalogSnapshot,
)
from aiosh_mcp.incident_runbook_policy import (
    MAX_RUNBOOK_POLICY_BYTES,
    RUNBOOKPOL_ERR_IO,
    RUNBOOKPOL_ERR_POLICY_VIOLATION,
    RUNBOOKPOL_ERR_SCAN_BOUNDS,
    RUNBOOKPOL_ERR_VALIDATION,
    RunbookEnforcementMode,
    RunbookSecurityPolicy,
)


def test_unit_boundary_step_timeouts():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    malware = baseline.get_runbook("RB-IR-MALWARE-01")
    assert malware is not None
    step = malware.steps[0]

    policy = RunbookSecurityPolicy(max_step_timeout_seconds=30)

    # 30s passes
    step.timeout_seconds = 30
    policy.evaluate_step_advance(step, operator_confirmed=True)

    # 31s fails
    step.timeout_seconds = 31
    with pytest.raises(ValueError, match=RUNBOOKPOL_ERR_POLICY_VIOLATION):
        policy.evaluate_step_advance(step, operator_confirmed=True)


def test_unit_boundary_scan_ports_and_depth():
    policy = RunbookSecurityPolicy(max_scanned_ports=100, max_file_scan_depth=5)

    # Exact port bound
    policy.evaluate_scan_operation("net", 100, 1)
    with pytest.raises(ValueError, match=RUNBOOKPOL_ERR_SCAN_BOUNDS):
        policy.evaluate_scan_operation("net", 101, 1)

    # Exact depth bound
    policy.evaluate_scan_operation("files", 1, 5)
    with pytest.raises(ValueError, match=RUNBOOKPOL_ERR_SCAN_BOUNDS):
        policy.evaluate_scan_operation("files", 1, 6)


def test_unit_disabled_enforcement_mode_bypass():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    access = baseline.get_runbook("RB-IR-ACCESS-01")
    assert access is not None
    step2 = access.steps[1]

    policy = RunbookSecurityPolicy(
        mode=RunbookEnforcementMode.DISABLED,
        disallowed_categories=[IncidentCategory.UNAUTHORIZED_ACCESS],
    )

    policy.evaluate_runbook_start(access)
    policy.evaluate_step_advance(step2, operator_confirmed=False)
    policy.evaluate_scan_operation("net", 999999, 999)


def test_unit_file_io_invalid_inputs_and_bounds():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Non-existent
        with pytest.raises(FileNotFoundError, match=RUNBOOKPOL_ERR_IO):
            RunbookSecurityPolicy.load_from_file("non_existent_policy.json")

        # Corrupted
        bad_p = Path(tmpdir) / "bad.json"
        bad_p.write_text("{ broken json", encoding="utf-8")
        with pytest.raises(Exception):
            RunbookSecurityPolicy.load_from_file(str(bad_p))

        # Oversized
        big_p = Path(tmpdir) / "big.json"
        big_p.write_bytes(b" " * (MAX_RUNBOOK_POLICY_BYTES + 1))
        with pytest.raises(ValueError, match=RUNBOOKPOL_ERR_IO):
            RunbookSecurityPolicy.load_from_file(str(big_p))
