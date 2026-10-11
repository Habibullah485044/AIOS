"""Integration Tests for Incident Response Runbooks Data Model (T-02968).

Tests cross-substrate JSON parity, canonical baseline schema verification,
and integration between Rust/Python representations.
"""

import json
import subprocess
import pytest

from aiosh_mcp.incident_runbook_data_model import (
    IncidentSeverity,
    IncidentCategory,
    RunbookPhase,
    RunbookTargetSubstrate,
    RunbookStep,
    RunbookSpec,
    RunbookCatalogSnapshot,
)


def test_cross_substrate_schema_conformance():
    """Verify Python baseline matches exact JSON fields expected by Rust."""
    py_snap = RunbookCatalogSnapshot.canonical_baseline()
    data = py_snap.to_dict()

    assert data["version"] == "1.0.0"
    assert "generated_at" in data
    assert isinstance(data["runbooks"], list)
    assert len(data["runbooks"]) == 2

    # Check first runbook: malware
    rb1 = data["runbooks"][0]
    assert rb1["id"] == "RB-IR-MALWARE-01"
    assert rb1["category"] == "malware_containment"
    assert rb1["severity"] == "high"
    assert len(rb1["steps"]) == 3
    assert rb1["steps"][0]["target"] == "process"
    assert rb1["steps"][0]["phase"] == "containment"
    assert rb1["steps"][1]["target"] == "network"
    assert rb1["steps"][2]["target"] == "audit_ring"
    assert rb1["steps"][2]["phase"] == "post_incident"

    # Check second runbook: unauthorized access
    rb2 = data["runbooks"][1]
    assert rb2["id"] == "RB-IR-ACCESS-01"
    assert rb2["category"] == "unauthorized_access"
    assert rb2["severity"] == "critical"
    assert len(rb2["steps"]) == 2
    assert rb2["steps"][0]["target"] == "identity"
    assert rb2["steps"][1]["target"] == "identity"
    assert rb2["steps"][1]["requires_confirmation"] is True


def test_cross_serialization_roundtrip_fidelity():
    """Verify full fidelity roundtrip through JSON serialization."""
    custom_step = RunbookStep(
        id="STEP-NET-ISOLATE",
        title="Apply packet drop rule via eBPF",
        phase=RunbookPhase.CONTAINMENT,
        target=RunbookTargetSubstrate.NETWORK,
        action_template="aiosh net filter drop --ip {attacker_ip}",
        automated=True,
        requires_confirmation=False,
        timeout_seconds=20,
    )

    custom_rb = RunbookSpec(
        id="RB-IR-DOS-01",
        title="Denial of Service Packet Mitigation",
        category=IncidentCategory.DENIAL_OF_SERVICE,
        severity=IncidentSeverity.HIGH,
        description="Immediate boundary filtering to alleviate saturation.",
        steps=[custom_step],
        tags=["dos", "network", "mitigation"],
    )

    catalog = RunbookCatalogSnapshot(
        version="1.1.0",
        runbooks=[custom_rb],
    )

    json_str = catalog.to_json()
    rehydrated = RunbookCatalogSnapshot.from_json(json_str)

    assert rehydrated.version == "1.1.0"
    assert len(rehydrated.runbooks) == 1
    rb_out = rehydrated.runbooks[0]
    assert rb_out.id == "RB-IR-DOS-01"
    assert rb_out.category == IncidentCategory.DENIAL_OF_SERVICE
    assert rb_out.severity == IncidentSeverity.HIGH
    assert len(rb_out.steps) == 1
    assert rb_out.steps[0].id == "STEP-NET-ISOLATE"
    assert rb_out.steps[0].target == RunbookTargetSubstrate.NETWORK
    assert rb_out.steps[0].phase == RunbookPhase.CONTAINMENT


def test_cross_substrate_enum_parity():
    """Verify all enums across substrates map to identical string representations."""
    severities = [s.value for s in IncidentSeverity]
    assert severities == ["low", "medium", "high", "critical"]

    categories = [c.value for c in IncidentCategory]
    expected_categories = [
        "malware_containment",
        "unauthorized_access",
        "data_exfiltration",
        "denial_of_service",
        "integrity_violation",
        "policy_bypass_attempt",
    ]
    assert categories == expected_categories

    phases = [p.value for p in RunbookPhase]
    assert phases == [
        "preparation",
        "detection",
        "containment",
        "eradication",
        "recovery",
        "post_incident",
    ]

    targets = [t.value for t in RunbookTargetSubstrate]
    assert targets == ["process", "network", "identity", "audit_ring", "storage"]
