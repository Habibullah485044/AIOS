"""Integration tests for Compliance Mapping Security Policy (T-02928).

Verifies service integration across registration, status update, assessment,
and storage persistence with active policy enforcement.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from aiosh_mcp.compliance import (
    canonical_baseline,
    build_entry,
    register_mapping,
    update_status,
    save_store,
    load_store,
    assess_framework,
)
from aiosh_mcp.compliance_policy import (
    ComplianceSecurityPolicy,
    CompliancePolicyMode,
    COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED,
    COMPLIANCEPOL_ERR_THREAT_REQUIRED,
    COMPLIANCEPOL_ERR_MITIGATION_REQUIRED,
    COMPLIANCEPOL_ERR_THRESHOLD_UNMET,
)


def test_compliance_policy_service_integration_e2e():
    snapshot = canonical_baseline()
    policy = ComplianceSecurityPolicy(
        permitted_frameworks=["nist_sp_800_53_rev5", "soc2_type2", "cis_controls_v8"],
        min_compliant_percentage=80.0,
    )

    # 1. Prohibited framework rejection
    entry_hipaa = build_entry(
        id="map-hipaa-01",
        control_id="164.312",
        framework="hipaa_security",
        target_type="pep_gate",
        target_ref="pep:gate:hipaa",
        status="non_compliant",
        threat_ids=["T-HIPAA-1"],
        mitigation_summary="",
        tags=["hipaa"],
    )
    with pytest.raises(ValueError, match=COMPLIANCEPOL_ERR_FRAMEWORK_PROHIBITED):
        register_mapping(snapshot, entry_hipaa, policy=policy)

    # 2. Missing threat rejection
    entry_no_threat = build_entry(
        id="map-nist-no-threat",
        control_id="AC-2",
        framework="nist_sp_800_53_rev5",
        target_type="pep_gate",
        target_ref="pep:gate:ac2",
        status="non_compliant",
        threat_ids=[],
        mitigation_summary="",
        tags=["nist"],
    )
    with pytest.raises(ValueError, match=COMPLIANCEPOL_ERR_THREAT_REQUIRED):
        register_mapping(snapshot, entry_no_threat, policy=policy)

    # 3. Valid registration
    entry_valid = build_entry(
        id="map-nist-valid",
        control_id="AC-2",
        framework="nist_sp_800_53_rev5",
        target_type="pep_gate",
        target_ref="pep:gate:ac2",
        status="non_compliant",
        threat_ids=["T-EOP-001"],
        mitigation_summary="",
        tags=["nist"],
    )
    register_mapping(snapshot, entry_valid, policy=policy)
    assert any(m.id == "map-nist-valid" for m in snapshot.mappings)

    # 4. Status transition gating
    with pytest.raises(ValueError, match=COMPLIANCEPOL_ERR_MITIGATION_REQUIRED):
        update_status(snapshot, "map-nist-valid", "compliant", reason="", policy=policy)

    update_status(snapshot, "map-nist-valid", "compliant", reason="PEP gate validated", policy=policy)
    entry = next(m for m in snapshot.mappings if m.id == "map-nist-valid")
    assert entry.status == "compliant"

    # 5. Assessment evaluation under policy
    assessment = assess_framework(snapshot, framework="nist_sp_800_53_rev5")
    verdict = policy.evaluate_assessment(assessment)
    assert verdict.verdict == "permit"

    # Strict threshold
    strict_policy = ComplianceSecurityPolicy(min_compliant_percentage=100.0)
    # Add non-compliant mapping
    entry_pending = build_entry(
        id="map-nist-pending",
        control_id="AC-4",
        framework="nist_sp_800_53_rev5",
        target_type="pep_gate",
        target_ref="pep:gate:ac4",
        status="non_compliant",
        threat_ids=["T-EOP-001"],
        mitigation_summary="",
        tags=["nist"],
    )
    register_mapping(snapshot, entry_pending)
    assessment2 = assess_framework(snapshot, framework="nist_sp_800_53_rev5")
    verdict2 = strict_policy.evaluate_assessment(assessment2)
    assert verdict2.verdict == "deny"
    assert verdict2.code == COMPLIANCEPOL_ERR_THRESHOLD_UNMET

    # 6. Store persistence roundtrip
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
        p = Path(tmpdir) / "compliance.json"
        save_store(str(p), snapshot)
        loaded = load_store(str(p))
        assert len(loaded.mappings) == len(snapshot.mappings)
