"""Implementation tests for Incident Response Runbooks Security Policy in Python (T-03026)."""

import tempfile
from pathlib import Path
import pytest

from aiosh_mcp.incident_runbook_data_model import (
    IncidentCategory,
    RunbookCatalogSnapshot,
    RunbookTargetSubstrate,
)
from aiosh_mcp.incident_runbook_policy import (
    RUNBOOKPOL_ERR_CATEGORY_DISALLOWED,
    RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED,
    RUNBOOKPOL_ERR_POLICY_VIOLATION,
    RUNBOOKPOL_ERR_SUBSTRATE_DISALLOWED,
    RunbookSecurityPolicy,
)


def test_policy_implementation_evaluation_matrix():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    malware = baseline.get_runbook("RB-IR-MALWARE-01")
    access = baseline.get_runbook("RB-IR-ACCESS-01")
    assert malware is not None and access is not None

    policy = RunbookSecurityPolicy()

    # Default policy allows canonical
    policy.evaluate_runbook_start(malware)
    policy.evaluate_runbook_start(access)

    # Disallow category
    policy.disallowed_categories.append(IncidentCategory.MALWARE_CONTAINMENT)
    with pytest.raises(ValueError, match=RUNBOOKPOL_ERR_CATEGORY_DISALLOWED):
        policy.evaluate_runbook_start(malware)

    # Disallow substrate
    policy.disallowed_categories.clear()
    policy.disallowed_substrates.append(RunbookTargetSubstrate.NETWORK)
    with pytest.raises(ValueError, match=RUNBOOKPOL_ERR_SUBSTRATE_DISALLOWED):
        policy.evaluate_runbook_start(malware)


def test_policy_implementation_step_advance_and_confirmation_gate():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    access = baseline.get_runbook("RB-IR-ACCESS-01")
    assert access is not None
    step2 = access.steps[1]

    policy = RunbookSecurityPolicy()

    # Unconfirmed step fails
    with pytest.raises(ValueError, match=RUNBOOKPOL_ERR_CONFIRMATION_REQUIRED):
        policy.evaluate_step_advance(step2, operator_confirmed=False)

    # Confirmed step passes
    policy.evaluate_step_advance(step2, operator_confirmed=True)

    # Timeout violation
    bad_step = step2
    bad_step.timeout_seconds = 120
    with pytest.raises(ValueError, match=RUNBOOKPOL_ERR_POLICY_VIOLATION):
        policy.evaluate_step_advance(bad_step, operator_confirmed=True)


def test_policy_implementation_file_io_roundtrip():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = str(Path(tmpdir) / "policy.json")

        policy = RunbookSecurityPolicy(
            max_step_timeout_seconds=88,
            disallowed_categories=[IncidentCategory.DENIAL_OF_SERVICE],
        )

        policy.save_to_file(path)
        loaded = RunbookSecurityPolicy.load_from_file(path)

        assert loaded.max_step_timeout_seconds == 88
        assert loaded.disallowed_categories == [IncidentCategory.DENIAL_OF_SERVICE]
