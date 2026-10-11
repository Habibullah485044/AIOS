"""Integration Tests for Compliance Mapping Observability (T-02938)."""

import json
from pathlib import Path
import tempfile
import pytest

from aiosh_mcp.server import aios_compliance
from aiosh_mcp.compliance import (
    ComplianceCatalogSnapshot,
    ComplianceMappingEntry,
    canonical_baseline,
)
from aiosh_mcp.compliance_observability import ComplianceObservabilityReport


def test_compliance_observability_mcp_integration_e2e(monkeypatch):
    # Set up temp dir for compliance map and audit ring
    with tempfile.TemporaryDirectory(prefix="compliance-obs-int-") as tmp:
        tmp_path = Path(tmp)
        map_path = tmp_path / "compliance_map.json"
        db_path = tmp_path / "audit_ring.db"

        # Baseline snapshot written to map_path
        baseline = canonical_baseline()
        from aiosh_mcp.compliance import save_store
        save_store(str(map_path), baseline)

        monkeypatch.setenv("AIOSH_COMPLIANCE_MAP_PATH", str(map_path))
        monkeypatch.setenv("AIOSH_AUDIT_DB", str(db_path))

        # Call aios_compliance via MCP tool surface
        res = aios_compliance(action="stats")

        assert res.get("ok") is True
        assert res.get("action") == "stats"
        assert "audit_id" in res
        assert res["audit_id"] is not None

        rep_dict = res.get("report")
        assert rep_dict is not None
        assert rep_dict["total_mappings"] == len(baseline.mappings)
        assert rep_dict["is_healthy"] is True
        assert "nist_sp_800_53_rev5" in rep_dict["mappings_by_framework"]

        # Parse and validate report object
        report = ComplianceObservabilityReport(**rep_dict)
        report.validate()
