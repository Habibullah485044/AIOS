"""Scaffold tests for Incident Response Runbooks Observability in Python (T-03035)."""

import pytest

from aiosh_mcp.incident_runbook_observability import (
    MAX_OBSERVABILITY_ENTRIES,
    MAX_OBSERVABILITY_PAYLOAD_BYTES,
    MAX_OBSERVABILITY_TEXT_LEN,
    IROBS_ERR_INACCESSIBLE,
    IROBS_ERR_VALIDATION,
    RunbookObservabilityService,
    RunbookObservabilitySnapshot,
)
from aiosh_mcp.incident_runbook_policy import RunbookEnforcementMode


def test_observability_scaffold_constants_and_types() -> None:
    assert MAX_OBSERVABILITY_PAYLOAD_BYTES == 64 * 1024
    assert MAX_OBSERVABILITY_ENTRIES == 128
    assert MAX_OBSERVABILITY_TEXT_LEN == 256
    assert IROBS_ERR_VALIDATION == "IROBS_ERR_VALIDATION"
    assert IROBS_ERR_INACCESSIBLE == "IROBS_ERR_INACCESSIBLE"

    snapshot = RunbookObservabilitySnapshot(
        generated_at_utc="2026-10-15T14:00:00Z",
        total_catalog_runbooks=2,
        total_executions=10,
        policy_mode=RunbookEnforcementMode.ENFORCING,
    )
    assert snapshot.total_catalog_runbooks == 2
    assert snapshot.is_healthy is True


def test_observability_scaffold_default_generation() -> None:
    snap = RunbookObservabilityService.generate_snapshot()
    assert snap.total_catalog_runbooks == 2
    assert snap.is_healthy is True


