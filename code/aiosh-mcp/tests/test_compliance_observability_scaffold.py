"""Implementation smoke test for Compliance Mapping Observability (T-02936)."""

from aiosh_mcp.compliance_observability import (
    COMPOBS_ERR_VALIDATION,
    COMPOBS_ERR_SERVICE_INACCESSIBLE,
    ComplianceObservabilityReport,
    sanitize_telemetry_text,
    generate_compliance_observability_report,
)
from aiosh_mcp.compliance import execute, canonical_baseline


def test_observability_implementation_smoke():
    assert COMPOBS_ERR_VALIDATION == "COMPOBS_ERR_VALIDATION"
    assert COMPOBS_ERR_SERVICE_INACCESSIBLE == "COMPOBS_ERR_SERVICE_INACCESSIBLE"
    assert sanitize_telemetry_text("hello\x00world") == "helloworld"

    # Test baseline snapshot report generation
    snap = canonical_baseline()
    report = generate_compliance_observability_report(snap)
    assert report.total_mappings == len(snap.mappings)
    assert report.is_healthy is True
    assert "nist_sp_800_53_rev5" in report.mappings_by_framework
    assert report.capacity_utilization_percent >= 0

    # Test via execute("stats")
    res = execute(action="stats")
    assert res["ok"] is True
    assert res["action"] == "stats"
    assert "report" in res
    assert res["report"]["total_mappings"] > 0
