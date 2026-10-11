"""Comprehensive Unit Tests for Incident Response Runbooks Data Model (T-02967).

Covers invariants IR-INV1..IR-INV5, validation bounds, enum parsing,
query methods, catalog operations, and JSON roundtrip serialization.
"""

import pytest

from aiosh_mcp.incident_runbook_data_model import (
    IncidentSeverity,
    IncidentCategory,
    RunbookPhase,
    RunbookTargetSubstrate,
    RunbookStep,
    RunbookSpec,
    RunbookCatalogSnapshot,
    validate_identifier,
    validate_title,
    validate_text_length,
    RUNBOOK_ERR_INVALID_ID,
    RUNBOOK_ERR_INVALID_TITLE,
    RUNBOOK_ERR_BOUNDS_EXCEEDED,
    RUNBOOK_ERR_CONTROL_CHARS,
    RUNBOOK_ERR_DUPLICATE_ID,
    RUNBOOK_ERR_EMPTY_STEPS,
)


def test_severity_parsing_and_values():
    assert IncidentSeverity.parse_severity("low") == IncidentSeverity.LOW
    assert IncidentSeverity.parse_severity("medium") == IncidentSeverity.MEDIUM
    assert IncidentSeverity.parse_severity("med") == IncidentSeverity.MEDIUM
    assert IncidentSeverity.parse_severity("high") == IncidentSeverity.HIGH
    assert IncidentSeverity.parse_severity("critical") == IncidentSeverity.CRITICAL
    assert IncidentSeverity.parse_severity("crit") == IncidentSeverity.CRITICAL
    with pytest.raises(ValueError):
        IncidentSeverity.parse_severity("unknown")


def test_category_parsing_and_values():
    assert IncidentCategory.parse_category("malware_containment") == IncidentCategory.MALWARE_CONTAINMENT
    assert IncidentCategory.parse_category("malware") == IncidentCategory.MALWARE_CONTAINMENT
    assert IncidentCategory.parse_category("unauthorized_access") == IncidentCategory.UNAUTHORIZED_ACCESS
    assert IncidentCategory.parse_category("access") == IncidentCategory.UNAUTHORIZED_ACCESS
    assert IncidentCategory.parse_category("data_exfiltration") == IncidentCategory.DATA_EXFILTRATION
    assert IncidentCategory.parse_category("denial_of_service") == IncidentCategory.DENIAL_OF_SERVICE
    assert IncidentCategory.parse_category("integrity_violation") == IncidentCategory.INTEGRITY_VIOLATION
    assert IncidentCategory.parse_category("policy_bypass_attempt") == IncidentCategory.POLICY_BYPASS_ATTEMPT
    with pytest.raises(ValueError):
        IncidentCategory.parse_category("unknown")


def test_phase_parsing_and_values():
    assert RunbookPhase.parse_phase("preparation") == RunbookPhase.PREPARATION
    assert RunbookPhase.parse_phase("prep") == RunbookPhase.PREPARATION
    assert RunbookPhase.parse_phase("detection") == RunbookPhase.DETECTION
    assert RunbookPhase.parse_phase("containment") == RunbookPhase.CONTAINMENT
    assert RunbookPhase.parse_phase("eradication") == RunbookPhase.ERADICATION
    assert RunbookPhase.parse_phase("recovery") == RunbookPhase.RECOVERY
    assert RunbookPhase.parse_phase("post_incident") == RunbookPhase.POST_INCIDENT
    with pytest.raises(ValueError):
        RunbookPhase.parse_phase("invalid")


def test_target_parsing_and_values():
    assert RunbookTargetSubstrate.parse_target("process") == RunbookTargetSubstrate.PROCESS
    assert RunbookTargetSubstrate.parse_target("proc") == RunbookTargetSubstrate.PROCESS
    assert RunbookTargetSubstrate.parse_target("network") == RunbookTargetSubstrate.NETWORK
    assert RunbookTargetSubstrate.parse_target("identity") == RunbookTargetSubstrate.IDENTITY
    assert RunbookTargetSubstrate.parse_target("audit_ring") == RunbookTargetSubstrate.AUDIT_RING
    assert RunbookTargetSubstrate.parse_target("storage") == RunbookTargetSubstrate.STORAGE
    with pytest.raises(ValueError):
        RunbookTargetSubstrate.parse_target("invalid")


def test_ir_inv1_identifier_validation():
    validate_identifier("VALID_ID-01.test", "id")
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_ID):
        validate_identifier("", "id")
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_ID):
        validate_identifier("   ", "id")
    with pytest.raises(ValueError, match=RUNBOOK_ERR_BOUNDS_EXCEEDED):
        validate_identifier("A" * 65, "id")
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_ID):
        validate_identifier("invalid@char", "id")
    with pytest.raises(ValueError, match=RUNBOOK_ERR_INVALID_ID):
        validate_identifier("has space", "id")


def test_ir_inv2_control_character_rejection():
    validate_title("Valid Title 123", "title")
    with pytest.raises(ValueError, match=RUNBOOK_ERR_CONTROL_CHARS):
        validate_title("Title with \x00 null byte", "title")
    with pytest.raises(ValueError, match=RUNBOOK_ERR_CONTROL_CHARS):
        validate_title("Title with \x1b escape code", "title")

    validate_text_length("Valid description\nwith newline", 2048, "desc")
    with pytest.raises(ValueError, match=RUNBOOK_ERR_CONTROL_CHARS):
        validate_text_length("Desc with \x07 bell", 2048, "desc")


def test_ir_inv3_and_inv4_runbook_validation_bounds():
    step = RunbookStep(
        id="STEP-1",
        title="Step 1",
        phase=RunbookPhase.CONTAINMENT,
        target=RunbookTargetSubstrate.PROCESS,
        action_template="echo contain",
        automated=True,
        requires_confirmation=False,
        timeout_seconds=15,
    )

    # Empty steps rejected (IR-INV4)
    with pytest.raises(ValueError, match=RUNBOOK_ERR_EMPTY_STEPS):
        RunbookSpec(
            id="RB-01",
            title="Test RB",
            category=IncidentCategory.MALWARE_CONTAINMENT,
            severity=IncidentSeverity.HIGH,
            description="Desc",
            steps=[],
            tags=["tag"],
        )

    # Duplicate step IDs rejected
    step_dup2 = RunbookStep(
        id="STEP-1",
        title="Step 2 with same ID",
        phase=RunbookPhase.CONTAINMENT,
        target=RunbookTargetSubstrate.PROCESS,
        action_template="echo contain2",
    )
    with pytest.raises(ValueError, match=RUNBOOK_ERR_DUPLICATE_ID):
        RunbookSpec(
            id="RB-01",
            title="Test RB",
            category=IncidentCategory.MALWARE_CONTAINMENT,
            severity=IncidentSeverity.HIGH,
            description="Desc",
            steps=[step, step_dup2],
            tags=["tag"],
        )

    # Exceed max steps (> 32)
    many_steps = [
        RunbookStep(
            id=f"STEP-{i:02d}",
            title=f"Step {i}",
            phase=RunbookPhase.CONTAINMENT,
            target=RunbookTargetSubstrate.PROCESS,
            action_template="cmd",
        )
        for i in range(33)
    ]
    with pytest.raises(ValueError, match=RUNBOOK_ERR_BOUNDS_EXCEEDED):
        RunbookSpec(
            id="RB-01",
            title="Test RB",
            category=IncidentCategory.MALWARE_CONTAINMENT,
            severity=IncidentSeverity.HIGH,
            description="Desc",
            steps=many_steps,
        )

    # Exceed max tags (> 16)
    many_tags = [f"tag{i}" for i in range(17)]
    with pytest.raises(ValueError, match=RUNBOOK_ERR_BOUNDS_EXCEEDED):
        RunbookSpec(
            id="RB-01",
            title="Test RB",
            category=IncidentCategory.MALWARE_CONTAINMENT,
            severity=IncidentSeverity.HIGH,
            description="Desc",
            steps=[step],
            tags=many_tags,
        )


def test_runbook_spec_query_methods():
    s1 = RunbookStep(
        id="S1",
        title="Step 1",
        phase=RunbookPhase.CONTAINMENT,
        target=RunbookTargetSubstrate.PROCESS,
        action_template="cmd1",
        automated=True,
        requires_confirmation=False,
        timeout_seconds=10,
    )
    s2 = RunbookStep(
        id="S2",
        title="Step 2",
        phase=RunbookPhase.CONTAINMENT,
        target=RunbookTargetSubstrate.NETWORK,
        action_template="cmd2",
        automated=False,
        requires_confirmation=True,
        timeout_seconds=20,
    )
    s3 = RunbookStep(
        id="S3",
        title="Step 3",
        phase=RunbookPhase.POST_INCIDENT,
        target=RunbookTargetSubstrate.AUDIT_RING,
        action_template="cmd3",
        automated=True,
        requires_confirmation=False,
        timeout_seconds=30,
    )

    rb = RunbookSpec(
        id="RB-QUERY-01",
        title="Query Test",
        category=IncidentCategory.MALWARE_CONTAINMENT,
        severity=IncidentSeverity.MEDIUM,
        description="Query test description",
        steps=[s1, s2, s3],
        tags=["test", "query"],
    )

    assert len(rb.steps_for_phase(RunbookPhase.CONTAINMENT)) == 2
    assert len(rb.steps_for_phase("post_incident")) == 1
    assert len(rb.steps_for_phase(RunbookPhase.ERADICATION)) == 0

    assert len(rb.steps_for_target(RunbookTargetSubstrate.PROCESS)) == 1
    assert len(rb.steps_for_target("network")) == 1
    assert len(rb.steps_for_target(RunbookTargetSubstrate.STORAGE)) == 0

    assert len(rb.automated_steps()) == 2
    assert len(rb.manual_steps()) == 1
    assert rb.total_timeout_seconds() == 60
    rb.validate()


def test_catalog_snapshot_operations_and_filters():
    catalog = RunbookCatalogSnapshot.canonical_baseline()
    assert len(catalog.runbooks) == 2

    # Filter by category
    mw = catalog.find_by_category("malware_containment")
    assert len(mw) == 1
    assert mw[0].id == "RB-IR-MALWARE-01"

    # Filter by severity
    crit = catalog.find_by_severity(IncidentSeverity.CRITICAL)
    assert len(crit) == 1
    assert crit[0].id == "RB-IR-ACCESS-01"

    # Filter by phase
    post = catalog.filter_by_phase(RunbookPhase.POST_INCIDENT)
    assert len(post) == 1

    # Filter by target
    net = catalog.filter_by_target(RunbookTargetSubstrate.NETWORK)
    assert len(net) == 1

    # Filter by tag
    tagged = catalog.filter_by_tag("emergency")
    assert len(tagged) == 1

    # Add duplicate ID rejected
    with pytest.raises(ValueError, match=RUNBOOK_ERR_DUPLICATE_ID):
        catalog.add_runbook(catalog.runbooks[0])

    # Get runbook
    assert catalog.get_runbook("RB-IR-MALWARE-01") is not None
    assert catalog.get_runbook("NON-EXISTENT") is None

    # Remove runbook
    removed = catalog.remove_runbook("RB-IR-MALWARE-01")
    assert removed is not None
    assert len(catalog.runbooks) == 1
    assert catalog.get_runbook("RB-IR-MALWARE-01") is None


def test_json_roundtrip_serialization():
    baseline = RunbookCatalogSnapshot.canonical_baseline()
    json_str = baseline.to_json(indent=2)
    assert len(json_str) > 0

    deserialized = RunbookCatalogSnapshot.from_json(json_str)
    assert baseline.version == deserialized.version
    assert len(baseline.runbooks) == len(deserialized.runbooks)
    assert baseline.runbooks[0].id == deserialized.runbooks[0].id
    assert len(baseline.runbooks[0].steps) == len(deserialized.runbooks[0].steps)
