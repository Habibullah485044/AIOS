"""Scaffold tests for Incident Response Runbooks Data Model (T-02965)."""

from aiosh_mcp.incident_runbook_data_model import (
    IncidentSeverity,
    IncidentCategory,
    RunbookPhase,
    RunbookTargetSubstrate,
    RunbookCatalogSnapshot,
)


def test_incident_runbook_scaffold_types():
    assert IncidentSeverity.LOW.value == "low"
    assert IncidentSeverity.CRITICAL.value == "critical"
    assert IncidentSeverity.parse_severity("high") == IncidentSeverity.HIGH

    assert IncidentCategory.MALWARE_CONTAINMENT.value == "malware_containment"
    assert IncidentCategory.UNAUTHORIZED_ACCESS.value == "unauthorized_access"

    assert RunbookPhase.CONTAINMENT.value == "containment"
    assert RunbookTargetSubstrate.PROCESS.value == "process"


def test_incident_runbook_canonical_baseline_scaffold():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    assert baseline.version == "1.0.0"
    assert len(baseline.runbooks) == 2

    malware_rb = baseline.get_runbook("RB-IR-MALWARE-01")
    assert malware_rb is not None
    assert malware_rb.severity == IncidentSeverity.HIGH
    assert len(malware_rb.steps) == 3

    access_rb = baseline.get_runbook("RB-IR-ACCESS-01")
    assert access_rb is not None
    assert access_rb.severity == IncidentSeverity.CRITICAL
    assert len(access_rb.steps) == 2
