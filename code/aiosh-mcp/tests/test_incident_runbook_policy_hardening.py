"""Integration & Hardening tests for Incident Response Runbooks Security Policy (T-03030).

Tests error envelopes, boundary clamping, temp file cleanup, and fail-open audit rows.
"""

import tempfile
from pathlib import Path
import pytest

from aiosh_mcp.incident_runbook_data_model import (
    RunbookCatalogSnapshot,
)
from aiosh_mcp.incident_runbook_policy import (
    PolicyResultEnvelope,
    RunbookEnforcementMode,
    RunbookSecurityPolicy,
    RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED,
    RUNBOOKPOL_ERR_VALIDATION,
)


def test_hardening_bounds_validation_on_extremes() -> None:
    policy = RunbookSecurityPolicy(max_step_timeout_seconds=500)
    with pytest.raises(ValueError, match=RUNBOOKPOL_ERR_VALIDATION):
        policy.validate_bounds()

    policy2 = RunbookSecurityPolicy(max_scanned_ports=70_000)
    with pytest.raises(ValueError, match=RUNBOOKPOL_ERR_VALIDATION):
        policy2.validate_bounds()

    policy3 = RunbookSecurityPolicy(max_file_scan_depth=50)
    with pytest.raises(ValueError, match=RUNBOOKPOL_ERR_VALIDATION):
        policy3.validate_bounds()


def test_hardening_result_envelope_failure_modes() -> None:
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    access = baseline.get_runbook("RB-IR-ACCESS-01")
    assert access is not None
    step2 = access.steps[1]

    policy = RunbookSecurityPolicy()

    # Unconfirmed high risk step
    res = policy.evaluate_step_with_envelope(step2, False)
    assert not res.ok
    assert res.error_code == RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED
    assert res.audit_row_required

    # Confirmed high risk step
    res_confirmed = policy.evaluate_step_with_envelope(step2, True)
    assert res_confirmed.ok
    assert not res_confirmed.audit_row_required


def test_hardening_permissive_fail_open_writes_honest_audit() -> None:
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    access = baseline.get_runbook("RB-IR-ACCESS-01")
    assert access is not None
    step2 = access.steps[1]

    policy = RunbookSecurityPolicy(mode=RunbookEnforcementMode.PERMISSIVE)

    # Under Permissive mode, execution proceeds (ok = True) but honest audit row is strictly REQUIRED
    res = policy.evaluate_step_with_envelope(step2, False)
    assert res.ok
    assert res.audit_row_required, "ADR-0035 AF-2 requires honest audit on permissive bypass"


def test_hardening_atomic_save_and_cleanup_no_temp_leak() -> None:
    policy = RunbookSecurityPolicy()
    with tempfile.TemporaryDirectory() as td:
        target_path = Path(td) / "test_runbook_policy_hardening.json"
        policy.save_to_file(str(target_path))

        assert target_path.exists()
        loaded = RunbookSecurityPolicy.load_from_file(str(target_path))
        assert loaded.max_step_timeout_seconds == policy.max_step_timeout_seconds

        # Verify no leftover .tmp files
        tmp_files = list(Path(td).glob("*.tmp.*"))
        assert len(tmp_files) == 0, "No temporary files should leak"
