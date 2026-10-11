"""Scaffold stub test for Compliance Mapping Observability (T-02935)."""

import pytest
from aiosh_mcp.compliance_observability import (
    COMPOBS_ERR_VALIDATION,
    COMPOBS_ERR_SERVICE_INACCESSIBLE,
    ComplianceObservabilityReport,
    sanitize_telemetry_text,
    generate_compliance_observability_report,
)
from aiosh_mcp.compliance import execute


def test_scaffold_symbols_and_loud_fail():
    assert COMPOBS_ERR_VALIDATION == "COMPOBS_ERR_VALIDATION"
    assert COMPOBS_ERR_SERVICE_INACCESSIBLE == "COMPOBS_ERR_SERVICE_INACCESSIBLE"
    assert sanitize_telemetry_text("hello\x00world") == "helloworld"

    report = ComplianceObservabilityReport()
    with pytest.raises(NotImplementedError):
        report.validate()

    with pytest.raises(NotImplementedError):
        generate_compliance_observability_report(None)

    with pytest.raises(NotImplementedError):
        execute(action="stats")
