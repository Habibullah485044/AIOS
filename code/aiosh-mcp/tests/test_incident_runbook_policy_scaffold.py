"""Scaffold tests for Incident Response Runbooks Security Policy (T-03025)."""

import pytest
from aiosh_mcp.incident_runbook_data_model import RunbookCatalogSnapshot
from aiosh_mcp.incident_runbook_policy import (
    DEFAULT_MAX_STEP_TIMEOUT_SECS,
    RUNBOOKPOL_ERR_POLICY_VIOLATION,
    RUNBOOKPOL_ERR_VALIDATION,
    RunbookEnforcementMode,
    RunbookSecurityPolicy,
)


def test_policy_scaffold_default_initialization():
    policy = RunbookSecurityPolicy()
    assert policy.version == "1.0.0"
    assert policy.mode == RunbookEnforcementMode.ENFORCING
    assert policy.require_operator_confirmation_for_high_risk is True
    assert policy.max_step_timeout_seconds == DEFAULT_MAX_STEP_TIMEOUT_SECS
    assert policy.max_active_sessions == 100
    assert policy.require_pep_grant is True

    assert RUNBOOKPOL_ERR_VALIDATION == "RUNBOOKPOL_ERR_VALIDATION"
    assert RUNBOOKPOL_ERR_POLICY_VIOLATION == "RUNBOOKPOL_ERR_POLICY_VIOLATION"


def test_policy_scaffold_fail_loudly():
    policy = RunbookSecurityPolicy()
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    malware = baseline.get_runbook("RB-IR-MALWARE-01")
    assert malware is not None
    policy.evaluate_runbook_start(malware)
