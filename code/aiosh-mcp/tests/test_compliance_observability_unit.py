"""Comprehensive Unit Tests for Compliance Mapping Observability (T-02937)."""

import math
import pytest

from aiosh_mcp.compliance_observability import (
    COMPOBS_ERR_VALIDATION,
    COMPOBS_ERR_SERVICE_INACCESSIBLE,
    ComplianceObservabilityReport,
    sanitize_telemetry_text,
    generate_compliance_observability_report,
    MAX_OUTCOME_DISTRIBUTION_ENTRIES,
    MAX_TELEMETRY_TEXT_LEN,
)
from aiosh_mcp.compliance import (
    ComplianceCatalogSnapshot,
    ComplianceMappingEntry,
    canonical_baseline,
)
from aiosh_mcp.compliance_policy import ComplianceSecurityPolicy, CompliancePolicyMode


class FakeAuditRing:
    def __init__(self, rows):
        self._rows = rows

    def tail(self, limit: int):
        return self._rows[-limit:]


def make_test_mapping(id: str, fw: str, st: str, tt: str) -> ComplianceMappingEntry:
    return ComplianceMappingEntry(
        id=id,
        control_id="AC-1",
        framework=fw,
        target_type=tt,
        target_ref="kernel.test.component",
        threat_ids=["THREAT-01"],
        status=st,
        mitigation_summary="Documented mitigation summary" if st == "compliant" else "",
        tags=[],
    )


def test_empty_catalog_observability():
    snap = ComplianceCatalogSnapshot(version="1.0.0", mappings=[])
    report = generate_compliance_observability_report(snap)

    assert report.total_mappings == 0
    assert len(report.mappings_by_framework) == 0
    assert len(report.mappings_by_status) == 0
    assert len(report.mappings_by_target_type) == 0
    assert report.compliance_percentage == 100.0
    assert report.gap_control_count == 0
    assert report.policy_mode == "unconfigured"
    assert report.capacity_utilization_percent == 0
    assert report.is_healthy is True
    assert report.recent_audit_events_count == 0
    report.validate()


def test_populated_catalog_distributions():
    snap = ComplianceCatalogSnapshot(
        version="1.0.0",
        mappings=[
            make_test_mapping("MAP-01", "nist_sp_800_53_rev5", "compliant", "pep_gate"),
            make_test_mapping("MAP-02", "iso_27001_2022", "non_compliant", "audit_ring"),
            make_test_mapping("MAP-03", "soc2_type2", "partially_compliant", "pep_gate"),
        ],
    )
    report = generate_compliance_observability_report(snap)
    assert report.total_mappings == 3
    assert report.mappings_by_framework.get("nist_sp_800_53_rev5") == 1
    assert report.mappings_by_framework.get("iso_27001_2022") == 1
    assert report.mappings_by_framework.get("soc2_type2") == 1

    assert report.mappings_by_status.get("compliant") == 1
    assert report.mappings_by_status.get("non_compliant") == 1
    assert report.mappings_by_status.get("partially_compliant") == 1

    assert report.mappings_by_target_type.get("pep_gate") == 2
    assert report.mappings_by_target_type.get("audit_ring") == 1

    assert report.gap_control_count == 2
    assert abs(report.compliance_percentage - 33.333333333333336) < 1e-6
    assert report.is_healthy is True


def test_text_sanitization():
    assert sanitize_telemetry_text("normal_text") == "normal_text"
    assert sanitize_telemetry_text("control\x00\x07\x1bchars") == "controlchars"
    long_text = "a" * 500
    sanitized = sanitize_telemetry_text(long_text)
    assert len(sanitized) == MAX_TELEMETRY_TEXT_LEN


def test_policy_mode_reflection():
    snap = ComplianceCatalogSnapshot(version="1.0.0", mappings=[])
    pol = ComplianceSecurityPolicy(mode=CompliancePolicyMode.ENFORCING)
    report = generate_compliance_observability_report(snap, policy=pol)
    assert report.policy_mode == "enforcing"

    pol2 = ComplianceSecurityPolicy(mode=CompliancePolicyMode.PERMISSIVE)
    report2 = generate_compliance_observability_report(snap, policy=pol2)
    assert report2.policy_mode == "permissive"


def test_audit_ring_tail_correlation():
    snap = ComplianceCatalogSnapshot(version="1.0.0", mappings=[])
    ring = FakeAuditRing([
        {"tool": "aios.compliance", "command": "compliance register"},
        {"tool": "aios.compliance.status", "command": "compliance status"},
        {"tool": "aios.secret", "command": "secret store"},
    ])
    report = generate_compliance_observability_report(snap, ring=ring)
    assert report.recent_audit_events_count == 2


def test_validation_negative_rfc3339_timestamp():
    snap = ComplianceCatalogSnapshot(version="1.0.0", mappings=[])
    report = generate_compliance_observability_report(snap)

    report.generated_at_utc = ""
    with pytest.raises(ValueError, match=COMPOBS_ERR_VALIDATION):
        report.validate()

    report.generated_at_utc = "not-a-timestamp"
    with pytest.raises(ValueError, match=COMPOBS_ERR_VALIDATION):
        report.validate()


def test_validation_negative_percentage_nan_or_range():
    snap = ComplianceCatalogSnapshot(version="1.0.0", mappings=[])
    report = generate_compliance_observability_report(snap)

    report.compliance_percentage = -5.0
    with pytest.raises(ValueError, match=COMPOBS_ERR_VALIDATION):
        report.validate()

    report.compliance_percentage = 105.0
    with pytest.raises(ValueError, match=COMPOBS_ERR_VALIDATION):
        report.validate()

    report.compliance_percentage = float("nan")
    with pytest.raises(ValueError, match=COMPOBS_ERR_VALIDATION):
        report.validate()


def test_validation_negative_distribution_cardinality_bound():
    snap = ComplianceCatalogSnapshot(version="1.0.0", mappings=[])
    report = generate_compliance_observability_report(snap)

    report.mappings_by_framework = {f"fw_{i}": 1 for i in range(MAX_OUTCOME_DISTRIBUTION_ENTRIES + 1)}
    with pytest.raises(ValueError, match=COMPOBS_ERR_VALIDATION):
        report.validate()


def test_validation_negative_control_chars_in_keys():
    snap = ComplianceCatalogSnapshot(version="1.0.0", mappings=[])
    report = generate_compliance_observability_report(snap)

    report.mappings_by_framework["bad\x07key"] = 1
    with pytest.raises(ValueError, match=COMPOBS_ERR_VALIDATION):
        report.validate()


def test_capacity_utilization_boundary():
    snap = ComplianceCatalogSnapshot(version="1.0.0", mappings=[])
    report_empty = generate_compliance_observability_report(snap)
    assert report_empty.capacity_utilization_percent == 0

    mappings = [
        make_test_mapping(f"MAP-{i}", "nist_sp_800_53_rev5", "compliant", "pep_gate")
        for i in range(10)
    ]
    snap10 = ComplianceCatalogSnapshot(version="1.0.0", mappings=mappings)
    report10 = generate_compliance_observability_report(snap10)
    assert report10.capacity_utilization_percent == 0
    report10.validate()
